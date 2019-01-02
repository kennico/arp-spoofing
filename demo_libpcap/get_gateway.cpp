//
// Created by kenny on 1/3/19.
//

#include <cstring>
#include <zconf.h>
#include <arpa/inet.h>
#include <iostream>
#include "common.h"

int get_gateway_ip(const char *devname);
void* thread_receiver(void *);
void* thread_sender(void *);


int main(int argc, char* argv[]) {
    auto ip = get_gateway_ip("wlx502b73dc543f");
    char buf[32] = {};
    inet_ntop(AF_INET, &ip, buf, sizeof(buf));

    std::cout << buf << std::endl;
}

struct get_gateway_thread_args {
    int attempts{0};
    int ms_interval{50};
    int return_ip{0};
    int fd_snd{-1};
    int fd_rcv{-1};
};


int get_gateway_ip(const char *devname) {

    auto fd_snd = socket(AF_INET, SOCK_DGRAM, 0);
    /*
     * https://stackoverflow.com/a/13548622/8706476
     * socket(AF_INET, SOCK_RAW, 0)
     */
    auto fd_rcv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd_snd == -1 || fd_rcv == -1) {
        perror("socket()");
        exit(1);
    }

    auto fds = {fd_snd, fd_rcv};
    for(auto fd:fds) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, devname, static_cast<socklen_t>(strlen(devname) + 1))) {
            perror("setsockopt(SO_BINDTODEVICE)");
            exit(1);
        }
    }

    int ttl = 1;
    if (setsockopt(fd_snd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
        perror("setsockopt(IP_TTL=0)");
        exit(1);
    }


    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

    if(connect(fd_snd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == -1) {
        perror("connect");
        exit(1);
    }

    pthread_t threads[2] = {};

    get_gateway_thread_args args;
    args.attempts = 5;
    args.ms_interval = 50;
    args.fd_snd = fd_snd;
    args.fd_rcv = fd_rcv;

    pthread_create(&threads[0], nullptr, thread_sender, &args);
    pthread_create(&threads[1], nullptr, thread_receiver, &args);

    for (auto thread : threads) {
        pthread_join(thread, nullptr);
    }

    for (auto fd:fds) {
        close(fd);
    }

    return args.return_ip;
}

void *thread_sender(void * args) {
    auto pargs =(get_gateway_thread_args*)args;


    timeval tm{};
    tm.tv_sec = 0;
    tm.tv_usec = 1000 * pargs->ms_interval;

    while (pargs->attempts > 0 && pargs->return_ip == 0) {
        ssize_t bytes = send(pargs->fd_snd, "AAAABBBBCCCCDDDD", 16, 0);
        if (bytes == -1) {
            perror("send");
        }
        select(0, nullptr, nullptr, nullptr, &tm);
        pargs->attempts--;
    }

    return nullptr;
}

void *thread_receiver(void * args) {
    auto pargs = (get_gateway_thread_args*)args;

    sockaddr_in addr{};
    char buf[16] = {0};

    while (pargs->attempts > 0) {
        socklen_t len = sizeof(addr);

        auto bytes = recvfrom(pargs->fd_rcv, buf, sizeof(buf), 0,
                reinterpret_cast<sockaddr *>(&addr), &len);

        if (bytes == -1) {
            perror("recvfrom");
        } else {
            memcpy(&pargs->return_ip, &addr.sin_addr, sizeof(addr.sin_addr));
            break;
        }

    }

    return nullptr;
}


