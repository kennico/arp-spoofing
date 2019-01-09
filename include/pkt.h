//
// Created by kenny on 1/4/19.
//

#pragma once

#include <string>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAC_ADDRLEN 6
#define ETHER_HDR_LEN 14
#define ARP_HDR_LEN 28

namespace kni {


    using ipv4_t = in_addr;
    using ipv6_t = in6_addr;

    typedef struct {
        u_char data[MAC_ADDRLEN];
    } mac_t;

    std::string to_string(const ipv4_t &);

    std::string to_string(const ipv6_t &);

    std::string to_string(const mac_t &);

    int mac_pton(const char *, void *);

    char *mac_ntop(const void *, char *, socklen_t);
}
