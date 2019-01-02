//
// Created by kenny on 12/29/18.
//
#include <cstdio>
#include <cstdlib>
#include <cassert>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <memory.h>
#include <map>


#include "common.h"


void fatal_error(const char* src, const char* error) {
    fprintf(stderr, "Fatal error in %s():%s\n", src, error);
    exit(1);
}

std::string to_string(const sockaddr &addr) {
    char buffer[INET6_ADDRSTRLEN]={0};

    switch(addr.sa_family) {
        case AF_INET:
            assert(inet_ntop(AF_INET, &((const sockaddr_in&)addr).sin_addr, buffer, sizeof(buffer)));
            break;

        case AF_INET6:
            assert(inet_ntop(AF_INET6, &((const sockaddr_in6&)addr).sin6_addr, buffer, sizeof(buffer)));
            break;

        case AF_PACKET: {
            auto p = (const sockaddr_ll*)&addr;
            assert(p->sll_halen == 6);
            mac_ntop(p->sll_addr, buffer, sizeof(buffer));
            break;
        }
        default:
            return "";
    }

    return std::string(buffer);
}

std::string to_string_null(const sockaddr *addr) {
    return addr == nullptr? "" : to_string(*addr);
}

inline char h2i(char c) {
    if(std::isdigit(c)) {
        return c-'0';
    } else if (std::isalpha(c)) {
        if (std::isupper(c)) {
            return static_cast<char>(c - 'A' + 10);
        } else {
            return static_cast<char>(c - 'a' + 10);
        }
    } else {
        return -1;
    }
}

int mac_pton(const char* src, void* dst) {
    u_char buf[MAC_ADDRLEN] = {0};
    auto i = 0;
    while (i < MAC_ADDRLEN) {
        auto h = h2i(*(src++));
        auto l = h2i(*(src++));
        if (h == -1 || l == -1 ||
            (*(src++) != ':' && i < MAC_ADDRLEN - 1)) {
            break;
        }
        buf[i++] = ((u_char)h) << 4 + (u_char)l;
    }
    if (i != MAC_ADDRLEN) {
        return 0;
    } else {
        memcpy(dst, buf, MAC_ADDRLEN);
        return 1;
    }
}

char *mac_ntop(const void * pmac, char * buf, socklen_t bufsize) {
    auto src = static_cast<const u_char *>(pmac);
    snprintf(buf, bufsize, "%02X:%02X:%02X:%02X:%02X:%02X",
             src[0], src[1], src[2], src[3], src[4], src[5]);

    return buf;
}



