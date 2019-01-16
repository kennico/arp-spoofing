//
// Created by kenny on 1/4/19.
//

#pragma once

#include <cstring>
#include <cctype>
#include <cstdio>
#include <cassert>
#include <cerrno>

#include <initializer_list>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>

#include <pcap.h>

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

#define KNI_OUTPUT_LF(...) do {\
    fprintf(stdout, __VA_ARGS__);fprintf(stdout, "\n");\
}while(false)

#define KNI_OUTPUT(...) do {\
    fprintf(stdout, __VA_ARGS__);\
}while(false)
