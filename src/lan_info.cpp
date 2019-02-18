//
// Created by kenny on 1/6/19.
//

#include "hdrs.h"
#include "utils.h"
#include "lan_info.h"

namespace kni {

    /**
     * Returning true doesn't mean that certain hosts are discovered.
     * Caller shouldn't depend on the return value to determine if hosts are discovered and IPs are resolved into MACs.
     *
     * @param script
     * @param map where IPv4s and MACs are to be stored as key-value pairs
     * @return true on success, or false if system error occurs
     */
    bool get_arp_from(const char *script, arp_map &map) {
        KNI_LOG_DEBUG("%s - command: %s", __FUNCTION__, script);

        int ipn = 0;
        return command(script).read_line([&](const char *line, ssize_t len) -> bool {
            if (ipn == 0)
                return inet_pton(AF_INET, line, &ipn) == 1;

            mac_t mac;
            if (mac_pton(line, &mac) == 0)
                return false;
            map[to_string(*(ipv4_t *) &ipn)] = mac;

            return !(ipn = 0);
        });
    }

    bool fetch_cached_arp(arp_map &map) {
        return get_arp_from("arp -n | awk '$0 !~ \"incomplete\"' | "
                            R"(grep -oP '(\w{2}:){5}\w{2}|((\d+\.){3}\d+)')", map);
    }

    bool query_lan_arp(const char *network, arp_map &map) {
        auto script = std::string("nmap -sn ") + network + " | "
                                                           R"(grep -oP '(\w{2}:){5}\w{2}|((\d+\.){3}\d+)')";
        return get_arp_from(script.c_str(), map);
    }

    int get_gateway_ip(const char *dev) {
        char buf[64] = {0};
        sprintf(buf, R"(route -n | grep -P '^0\.0\.0\.0.+UG.+%s$')", dev);
        KNI_LOG_DEBUG("%s - command: %s", __FUNCTION__, buf);

        int ret = -1;
        command(buf).read_line([&](const char *line_buf, ssize_t len) -> bool {
            // Destination  Gateway         ...     Device
            // 0.0.0.0      192.168.1.1     ...     wlan0

            auto ip_begin = std::find_if(line_buf, line_buf + len, isspace);
            ip_begin = std::find_if(ip_begin, line_buf + len, isdigit);
            auto ip_end = std::find_if(ip_begin, line_buf + len, isspace);

            char ip_buf[4 * 4];
            memcpy(ip_buf, ip_begin, ip_end - ip_begin);

            // Don't care what inet_pton returns.
            // It's caller's duty to examine errno.
            inet_pton(AF_INET, ip_buf, &ret);

            return false;
        });

        return ret;
    }

    int get_device_info(const char *dev, devinfo_t *pinfo, char *errbuf) {
        pcap_if_t *if_info = nullptr;
        if (pcap_findalldevs(&if_info, errbuf) == PCAP_ERROR) {
            return -1;
        }

        auto info = if_info;
        while (info != nullptr) {
            if (strcmp(dev, info->name) == 0)
                break;
            info = info->next;
        }

        if (info == nullptr) {
            sprintf(errbuf, "Device \"%s\" not found.", dev);
            pcap_freealldevs(if_info);
            return -1;
        }

        devinfo_t tmpinfo;

        int found_mac = 0, found_ip = 0;

        auto sa = info->addresses;
        while (sa != nullptr) {
            if (sa->addr->sa_family == AF_INET) {
                assert(sa->addr != nullptr);

                auto ia = (sockaddr_in *) sa->addr;
                tmpinfo.ip = ia->sin_addr;

                ia = (sockaddr_in *) sa->broadaddr;
                if (ia != nullptr)
                    tmpinfo.ip_bcast = ia->sin_addr;
                else
                    KNI_LOG_WARN("dev: %s ip: %s BCAST address not found.",
                                 dev, to_string(tmpinfo.ip).c_str());

                ia = (sockaddr_in *) sa->netmask;
                if (ia != nullptr)
                    tmpinfo.ip_netmask = ia->sin_addr;
                else
                    KNI_LOG_WARN("dev: %s ip: %s netmask not found.",
                                 dev, to_string(tmpinfo.ip).c_str());

                found_ip = 1;

            } else if (sa->addr->sa_family == AF_PACKET) {
                assert(sa->addr != nullptr);

                auto lla = (sockaddr_ll *) (sa->addr);
                memcpy(&tmpinfo.hw_addr, lla->sll_addr, MAC_ADDRLEN);

                lla = (sockaddr_ll *) sa->broadaddr;
                if (lla)
                    memcpy(&tmpinfo.hw_bcast, lla->sll_addr, MAC_ADDRLEN);
                else
                    KNI_LOG_WARN("dev: %s mac: %s BCAST address not found.",
                                 dev, to_string(tmpinfo.hw_addr).c_str());

                found_mac = 1;
            }

            sa = sa->next;
        }

        if (!found_ip || !found_mac) {
            sprintf(errbuf, "Device \"%s\"'s IP or MAC address not found.", dev);
            pcap_freealldevs(if_info);
            return -1;
        }

        memcpy(pinfo, &tmpinfo, sizeof(tmpinfo));
        return 0;
    }


}