//
// Created by kenny on 12/29/18.
//

#include "pkt.h"
#include "hdrs.h"


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
}
