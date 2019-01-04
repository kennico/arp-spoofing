//
// Created by kenny on 1/4/19.
//

#include "hdrs.h"
#include "netinfo.h"
#include "pkt.h"




#define RETURN_ON(condition, ret) do{ \
    if (condition) {\
        return ret;\
    }\
} while(0)

#define RETURN_NEGATIVE_ON(condition) RETURN_ON(condition, -1)




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
        buf[i++] = (((u_char)h) << 4) + (u_char)l;
    }
    if (i != MAC_ADDRLEN) {
        return 0;
    } else {
        memcpy(dst, buf, MAC_ADDRLEN);
        return 1;
    }
}

/*
 * It always return true.
 */
char *mac_ntop(const void * pmac, char * buf, socklen_t bufsize) {
    auto src = static_cast<const u_char *>(pmac);
    snprintf(buf, bufsize, "%02X:%02X:%02X:%02X:%02X:%02X",
             src[0], src[1], src[2], src[3], src[4], src[5]);

    return buf;
}


int get_gateway_ip(const char *devname, int attempts, int ms) {

    auto sender = socket(AF_INET, SOCK_DGRAM, 0);
    RETURN_NEGATIVE_ON(sender == -1);
    /*
     * https://stackoverflow.com/a/13548622/8706476
     * socket(AF_INET, SOCK_RAW, 0)
     */
    auto listener = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    RETURN_NEGATIVE_ON(listener == -1);

    auto ret = 0;
    auto fds = {sender, listener};
    if (devname != nullptr) {
        for(auto fd:fds) {
            ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, devname, static_cast<socklen_t>(strlen(devname) + 1));
            RETURN_NEGATIVE_ON(ret == -1);
        }
    }

    int ttl = 1;
    ret = setsockopt(sender, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
    RETURN_NEGATIVE_ON(ret == -1);


    sockaddr_in dummy_addr{};
    dummy_addr.sin_family = AF_INET;
    dummy_addr.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &dummy_addr.sin_addr);

    ret = connect(sender, reinterpret_cast<const sockaddr *>(&dummy_addr), sizeof(dummy_addr));
    RETURN_NEGATIVE_ON(ret == -1);

    timeval slt_tm = {
            0,
            ms * 1000
    };

    constexpr const char* dummys = "AAAABBBBCCCCDDDD";
    constexpr const size_t dummys_len = strlen(dummys);

    sockaddr_in return_addr{};

    ssize_t bytes=0;
    while (attempts-- > 0 && bytes != dummys_len) {
        bytes = send(sender, dummys, dummys_len, 0);
        if (bytes == -1)
            continue;
        // calling select on icmp socket always returns 0 indicating timeouts.
        select(0, nullptr, nullptr, nullptr, &slt_tm);

        char buf[dummys_len];
        socklen_t len = sizeof(return_addr);
        bytes = recvfrom(listener, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&return_addr), &len);
    }

    for (auto fd:fds)
        close(fd);

    if (bytes == -1)
        return -1;
    else
        return *(int*)&return_addr.sin_addr;

}

int has_mac(const sockaddr *paddr) {
    if (paddr->sa_family == AF_PACKET) {
        auto lla = (const sockaddr_ll*)paddr;
        return lla->sll_halen == MAC_ADDRLEN;
    }
    return 0;
}
