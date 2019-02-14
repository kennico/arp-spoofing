//
// Created by kenny on 1/4/19.
//

#pragma once

#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <memory.h>

#define MAC_ADDRLEN     6
#define ETHER_HDRLEN    14
#define ARP_HDRLEN      28
#define IPV4_HDRLEN     20 // no options
#define IPV4_MAX_HDRLEN 60
#define TCP_HDRLEN      40 // no options
#define TCP_MAX_HDRLEN  60
#define IPV6_HDRLEN     40
#define PSEUDO_IPV4_HDRLEN (4*2+1*2+2)

namespace kni {

    typedef struct {
        u_char data[MAC_ADDRLEN];
    } mac_addr;

    using ipv4_t    = in_addr;
    using ipv6_t    = in6_addr;
    using mac_t     = mac_addr;
    using port_t    = uint16_t;

    inline bool operator==(const ipv4_t &a, const ipv4_t &b) {
        return *(uint32_t *) (&a) == *(uint32_t *) (&b);
    }

    inline bool operator==(const ipv6_t &a, const ipv6_t &b) {
        return memcmp(&a, &b, sizeof(ipv6_t)) == 0;
    }

    inline bool operator==(const mac_t &a, const mac_t &b) {
        return memcmp(a.data, b.data, sizeof(a.data)) == 0;
    }

    std::string to_string(const ipv4_t &);

    std::string to_string(const ipv6_t &);

    std::string to_string(const mac_t &);

    /**
     *
     * @return 1 on success
     */
    int mac_pton(const char *, void *);

    char *mac_ntop(const void *, char *, socklen_t);
}
