//
// Created by kenny on 1/4/19.
//

#pragma once

#include <sys/socket.h>

#define MAC_ADDRLEN 6
#define ETHER_HDR_LEN 14
#define ARP_HDR_LEN 28


using ipv4_t = in_addr;
using ipv6_t = in6_addr;
using mac_t = u_char [MAC_ADDRLEN];

int mac_pton(const char*, void*);
char* mac_ntop(const void*, char*, socklen_t);
int has_mac(const sockaddr *);