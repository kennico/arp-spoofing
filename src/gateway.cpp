//
// Created by kenny on 1/4/19.
//

#include "hdrs.h"
#include "lan_info.h"
#include "pkt.h"


#define RETURN_ON(condition, ret) do{ \
    if (condition) {\
        return ret;\
    }\
} while(0)

#define RETURN_NEGATIVE_ON(condition) RETURN_ON(condition, -1)


namespace kni {

    /**
     *
     * @param c 0-9a-fA-F
     * @return an integer[0~15] or -1
     */
    inline char h2i(char c) {
        if (std::isdigit(c))
            return c - '0';
        else if (std::isupper(c))
            return static_cast<char>(c - 'A' + 10);
        else if (std::islower(c))
            return static_cast<char>(c - 'a' + 10);
        else
            return -1;
    }

    int mac_pton(const char *src, void *dst) {
        u_char buf[MAC_ADDRLEN] = {0};
        auto i = 0;
        while (i < MAC_ADDRLEN) {
            auto h = h2i(*(src++));
            auto l = h2i(*(src++));
            if (h == -1 || l == -1 || (*(src++) != ':' && i < MAC_ADDRLEN - 1))
                break;
            buf[i++] = (((u_char) h) << 4) + (u_char) l; // NOLINT
        }

        if (i != MAC_ADDRLEN)
            return 0;

        memcpy(dst, buf, MAC_ADDRLEN);
        return 1;
    }

    /*
     * It always return true.
     */
    char *mac_ntop(const void *pmac, char *buf, socklen_t bufsize) {
        auto src = static_cast<const u_char *>(pmac);
        snprintf(buf, bufsize, "%02X:%02X:%02X:%02X:%02X:%02X",
                 src[0], src[1], src[2], src[3], src[4], src[5]);

        return buf;
    }

    int get_gateway_ip(const char *devname) {
        char command[64] = {0};
        sprintf(command, R"(route -n | grep -P '^0\.0\.0\.0.+UG.+%s$')", devname);
        KNI_LOG_DEBUG("%s - Command: %s", __FUNCTION__, command);

        auto fp = popen(command, "r");
        if (fp == nullptr)
            return -1;

        char *line_buf = nullptr;
        size_t bufsize = 0;
        auto len = getline(&line_buf, &bufsize, fp);
        if (len == -1)
            return -1;

        std::string line(line_buf);
        auto ws_pos = line.find_first_of(' ');
        auto nu_beg = line.find_first_not_of(' ', ws_pos);
        auto nu_end = line.find_first_of(' ', nu_beg);

        assert(nu_beg < nu_end);
        int ret = -1;
        inet_pton(AF_INET, line.substr(nu_beg, nu_end - nu_beg).c_str(), &ret);

        free(line_buf);
        pclose(fp);

        return ret;
    }

    int get_device_info(const char *devname, devinfo_t *pinfo, char *errbuf) {
        pcap_if_t *if_info = nullptr;
        if (pcap_findalldevs(&if_info, errbuf) == PCAP_ERROR) {
            return -1;
        }

        auto info = if_info;
        while (info != nullptr) {
            if (strcmp(devname, info->name) == 0)
                break;
            info = info->next;
        }

        if (info == nullptr) {
            sprintf(errbuf, "Device \"%s\" not found.", devname);
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
                                 devname, to_string(tmpinfo.ip).c_str());

                ia = (sockaddr_in *) sa->netmask;
                if (ia != nullptr)
                    tmpinfo.ip_netmask = ia->sin_addr;
                else
                    KNI_LOG_WARN("dev: %s ip: %s netmask not found.",
                                 devname, to_string(tmpinfo.ip).c_str());

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
                                 devname, to_string(tmpinfo.hw_addr).c_str());

                found_mac = 1;
            }

            sa = sa->next;
        }

        if (!found_ip || !found_mac) {
            sprintf(errbuf, "Device \"%s\"'s IP or MAC address not found.", devname);
            pcap_freealldevs(if_info);
            return -1;
        }

        memcpy(pinfo, &tmpinfo, sizeof(tmpinfo));

        return 0;
    }

}