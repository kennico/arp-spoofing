//
// Created by kenny on 2/1/19.
//

#pragma once

#include "hdrs.h"
#include "arpspf.h"

struct pthargs_spoof {
    int npackets{};
    int seconds{};
    bool twoway{};

    std::string victim_ip{};
    kni::mac_t victim_mac{};

    kni::lan_info *lan{nullptr};

    bool to_be_running{false};
    pthread_t thread_id{};
};

struct pthargs_hijack_http {

    kni::ipv4_t victim_ip{};
    kni::lan_info *lan;

    std::string devname{};

    kni::io_packet_base *io_packet{};

    pthread_t thread_id{};
};