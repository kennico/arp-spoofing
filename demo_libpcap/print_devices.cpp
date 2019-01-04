//
// Created by kenny on 12/29/18.
//

#include <pcap.h>
#include <cstdlib>
#include <cstdio>
#include <limits>
#include <cassert>

#include <iostream>
#include "arpspf.h"


int main(int argc, char* argv[]) {
    char errbuf[1024] = {0};
    pcap_if_t* ifaces= nullptr;

    int ret = pcap_findalldevs(&ifaces, errbuf);
    if (ret == PCAP_ERROR) {
        fatal_error("pcap_findalldevs", errbuf);
    } else if(ifaces == nullptr) {
        fatal_error("pcap_findalldevs", "No device found");
    }

    auto dev = ifaces;
    while (dev != nullptr) {
        std::cout << "Device " << dev->name
                  << " found\n\tFlags: " << dev->flags
                  << "\n\tDescriptions: " << (dev->description == nullptr?"":dev->description)
                  << "\n";

        auto pa = dev->addresses;
        while (pa != nullptr) {
            std::cout << "\n\tAddress: " << get_address_string(pa->addr)
                      << "\n\tNetmask: " << get_address_string(pa->netmask)
                      << "\n\tBroadcast: " << get_address_string(pa->broadaddr)
                      << "\n\tDestination: " << get_address_string(pa->dstaddr)
                      << "\n";
            pa = pa->next;
        }
        dev = dev->next;
    }

    pcap_freealldevs(ifaces);

}