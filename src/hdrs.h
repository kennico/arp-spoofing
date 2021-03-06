//
// Created by kenny on 1/4/19.
//

#pragma once

#include <string>
#include <map>
#include <queue>
#include <set>
#include <initializer_list>
#include <algorithm>
#include <memory>

#include <cstring>
#include <cctype>
#include <cstdio>
#include <cassert>
#include <cerrno>

#include <pthread.h>


#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>

#include <pcap.h>

// TODO Boost-style logger
// Thread safety about printf and other posix stream output functions
// https://stackoverflow.com/a/40186101/8706476

#ifdef KNI_DEBUG
#define KNI_LOG_DEBUG(...) do{\
    fprintf(stderr, "DEBUG: ");fprintf(stderr, __VA_ARGS__);fprintf(stderr, "\n");\
}while(false)

#define KNI_LOG_ERROR(...) do{\
    fprintf(stderr, "ERROR: %s() in %s(%d)\n\t",__FUNCTION__, __FILE__, __LINE__);fprintf(stderr, __VA_ARGS__);fprintf(stderr, "\n");\
}while(false)

#define KNI_LOG_WARN(...) do{\
    fprintf(stderr, "WARN : ");fprintf(stderr, __VA_ARGS__);fprintf(stderr, "\n");\
}while(false)

#else
#define KNI_LOG_DEBUG(...)
#define KNI_LOG_ERROR(...)
#define KNI_LOG_WARN(...)
#endif

#define KNI_PRINTLN(...) do {\
    fprintf(stdout, __VA_ARGS__);fprintf(stdout, "\n");\
}while(false)

#define KNI_PRINT(...) do {\
    fprintf(stdout, __VA_ARGS__);\
}while(false)

#define KNI_FATAL_ERROR(...) do {\
    fprintf(stderr, "FATAL: %s() in %s(%d)\n\t",__FUNCTION__, __FILE__, __LINE__);fprintf(stderr, __VA_ARGS__);fprintf(stderr, "\n");\
    exit(1);\
} while(false)
