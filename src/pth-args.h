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

    kni::netinfo *netdb{nullptr};

    bool to_be_running{false};
    pthread_t thread_id{};
};

struct pthargs_hijack_http {

    kni::ipv4_t victim_ip{};
    uint16_t httpd{};            // The port number httpd is listening

    kni::netinfo *netdb{nullptr};

    bool to_be_running{false};
    pthread_t thread_id{};
};