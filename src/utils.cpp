//
// Created by kenny on 1/4/19.
//

#include "hdrs.h"
#include "lan_info.h"
#include "pkt.h"


namespace kni {

    std::string to_string(const ipv4_t &ipv4) {
        char buf[16];
        assert(inet_ntop(AF_INET, &ipv4, buf, sizeof(buf)));
        return std::string(buf);
    }

    std::string to_string(const ipv6_t &ipv6) {
        char buf[INET6_ADDRSTRLEN] = {0};
        assert(inet_ntop(AF_INET6, &ipv6, buf, sizeof(buf)));
        return std::string(buf);
    }

    std::string to_string(const mac_t &mac) {
        char buf[3 * MAC_ADDRLEN];
        assert(mac_ntop(&mac, buf, sizeof(buf)));
        return std::string(buf);
    }

    std::string subnet(const ipv4_t &ip, const ipv4_t &mask) {
        return to_string(ip) + "/" + std::to_string(count_bits(*(unsigned int *) &mask));
    }

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
}