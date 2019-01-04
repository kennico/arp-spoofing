/*
 * Arguments:
 * victim's ip
 * how many packets
 * time interval
 * device name
 */


#include "arpspf.h"
#include "hdrs.h"

#include <wordexp.h>

#include <map>

#include <cstring>
#include <getopt.h>

const static size_t ERR_BUF_SIZE = 1024;
static char err_buf[ERR_BUF_SIZE];

static u_char dev_mac[MAC_ADDRLEN];
static u_char brd_mac[MAC_ADDRLEN] = {'\xff','\xff','\xff','\xff','\xff','\xff'};

#define APP_NAME "arpspf"

typedef int (*arpspf_func)(int , char*[]);

int arpspf_exit(int, char **);
int arpspf_spoof(int, char **);
int arpspf_scan_lan(int, char **);
int arpspf_forward(int, char **);
int arpspf_hijack(int, char **);

int main(int argc, char* argv[]) {
    if (argc == 1) {
        fatal_error(APP_NAME, "missing device name");
    }

    const char* dev = argv[1];

    pcap_if_t* if_info = nullptr;
    int ret = pcap_findalldevs(&if_info, err_buf);
    if (ret == PCAP_ERROR) {
        fatal_error("pcap_findalldevs", err_buf);
    } else if(if_info == nullptr) {
        fatal_error(APP_NAME, "no device found");
    }

    auto info = if_info;
    while (info != nullptr) {
        if (strcmp(dev, info->name) == 0) {
            break;
        }
        info = info->next;
    }

    if (info == nullptr) {
        fatal_error(APP_NAME, "Device not found");

    } else {
        auto sa = info->addresses;
        while (sa != nullptr) {
            if (has_mac(sa->broadaddr)) {
                auto lla = (sockaddr_ll*)(sa->addr);
                memcpy(brd_mac, lla->sll_addr, MAC_ADDRLEN);
            }
            if (has_mac(sa->addr)) {
                auto lla = (sockaddr_ll*)(sa->addr);
                memcpy(dev_mac, lla->sll_addr, MAC_ADDRLEN);
                break;
            }
            sa = sa->next;
        }

        if (sa == nullptr) {
            fatal_error(APP_NAME, "Device MAC not found");
        } else {
            printf("Device \"%s\": %s\n", dev, to_string(dev_mac).c_str());
        }
    }


    std::map<std::string, arpspf_func> cmds;

    cmds["exit"] = arpspf_exit;
    cmds["spf"] = arpspf_spoof;
    cmds["sc"] = arpspf_scan_lan;
    cmds["fwd"] = arpspf_forward;
    cmds["hij"] = arpspf_hijack;

    int keep_looping = 1;
    while (keep_looping) {
        char* line_buf = nullptr;
        size_t bufsize = 0;

        int bytes;
        char dmt;
        if ((bytes = static_cast<int>(getline(&line_buf, &bufsize, stdin))) > 1) {

            dmt = line_buf[bytes-1];
            line_buf[bytes-1] = 0;

            wordexp_t we{};
            ret = wordexp(line_buf, &we, 0);

            if (ret == 0) {
                std::string name(we.we_wordv[0]);
                if (cmds.count(name)) {
                    keep_looping = cmds[name](static_cast<int>(we.we_wordc), we.we_wordv);
                } else {
                    printf("Command \"%s\" not found.\n", we.we_wordv[0]);
                }
            } else if (ret != WRDE_BADCHAR && ret != WRDE_SYNTAX) {
                keep_looping = 0;
            }

            wordfree(&we);
            line_buf[bytes-1] = dmt;
        }

        free(line_buf);
    }


    return 0;
}

/*
 * sc - scan LAN ips
 *      sc 5
 *      sc
 * spf - perform LAN arp spoofing to hosts
 *      spf 192.168.225.187 -n 5 -c 100
 * fwd - forward network traffic between hosts
 *      fwd 192.168.225.187
 */

int arpspf_exit(int argc, char **argv) {
    return 0;
}

/*
 * spf - perform LAN arp spoofing on a single host
 *      spf 192.168.225.187 -n 5 -c 100
 */
int arpspf_spoof(int argc, char ** argv) {
    int opt;
    int seconds = 10, npackets = -1;
    while ((opt = getopt(argc, argv, "n:c:"))) {
        switch (opt) {
            case 'n':
                seconds = atoi(optarg);
                break;
            case 'c':
                npackets = atoi(optarg);
                break;
            default:
                break;
        }
    }

    if (seconds < 0 || npackets < 0) {
        printf("Invalid arguments.\n");
        return 1;
    }


    u_char buf[128] = {};

    fake_ether_hdr etherHdr(buf, ETHER_HDR_LEN);
    etherHdr.src = dev_mac;



    fake_arp_hdr arpHdr(buf+ETHER_HDR_LEN, sizeof(buf) - ETHER_HDR_LEN);

    return 1;
}

int arpspf_scan_lan(int, char **) {
    return 0;
}

int arpspf_forward(int, char **) {
    return 0;
}

int arpspf_hijack(int, char **) {
    return 0;
}

