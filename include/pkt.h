//
// Created by kenny on 1/4/19.
//

#pragma once

#include <string>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAC_ADDRLEN 6
#define ETHER_HDRLEN 14
#define ARP_HDRLEN 28
#define IPV4_BASE_HDRLEN 20

namespace kni {

    typedef struct {
        u_char data[MAC_ADDRLEN];
    } mac_addr;

    using ipv4_t    = in_addr;
    using ipv6_t    = in6_addr;
    using mac_t     = mac_addr;


    std::string to_string(const ipv4_t &);

    std::string to_string(const ipv6_t &);

    std::string to_string(const mac_t &);

    int mac_pton(const char *, void *);

    char *mac_ntop(const void *, char *, socklen_t);
}
