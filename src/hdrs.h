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

#ifdef KNI_DEBUG
#define LOG_DEBUG(...) do{\
    fprintf(stderr, "DEBUG: ");fprintf(stderr, __VA_ARGS__);fprintf(stderr, "\n");\
}while(false)

#define LOG_ERROR(...) do{\
    fprintf(stderr, "ERROR: %s() in %s(%d)\n\t",__FUNCTION__, __FILE__, __LINE__);fprintf(stderr, __VA_ARGS__);fprintf(stderr, "\n");\
}while(false)
#else
#define LOG_DEBUG(...)
#define LOG_ERROR(...)
#endif

namespace kni {
    int count_bits(unsigned int);
}