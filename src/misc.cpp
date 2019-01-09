//
// Created by kenny on 12/29/18.
//

#include "arpspf.h"
#include "hdrs.h"

void fatal_error(const char *src, const char *error) {
    LOG_ERROR("Fatal error in %s - %s\n", src, error);
    exit(1);
}

std::string get_address_string(const sockaddr *paddr) {
    if (paddr == nullptr)
        return "";

    char buffer[INET6_ADDRSTRLEN] = {0};

    switch (paddr->sa_family) {
        case AF_INET:
            return kni::to_string(((const sockaddr_in *) paddr)->sin_addr);

        case AF_INET6:
            return kni::to_string(((const sockaddr_in6 *) paddr)->sin6_addr);
            break;

        case AF_PACKET: {
            auto p = (const sockaddr_ll *) paddr;
            assert(p->sll_halen == 6);
            kni::mac_ntop(p->sll_addr, buffer, sizeof(buffer));
            break;
        }
        default:
            return "";
    }

    return std::string(buffer);
}


namespace kni {


    int count_bits(unsigned int n) {
        int count = 0;
        while (n) {
            if (n & 0x1)
                count++;
            n >>= 1;
        }
        return count;
    }

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
