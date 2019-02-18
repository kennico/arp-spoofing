//
// Created by kenny on 1/4/19.
//

#pragma once

#include <map>
#include <cstring>

#include "pkt.h"
#include "utils.h"

namespace kni {

    struct devinfo_t {
        mac_t hw_addr{};        // Hardware address
        mac_t hw_bcast{};       // Broadcast hardware address
        ipv4_t ip{};            // IPv4 address
        ipv4_t ip_bcast{};      // Broadcast IPv4 address
        ipv4_t ip_netmask{};    // Subnet mask
    };

    using arp_map = std::map<std::string, mac_t>;

    /**
     *
     * @param dev device name
     * @return an ip address in network byte order on success or -1 on failure and error info can be retrieved via errno
     */
    int get_gateway_ip(const char *dev);

    /**
     *
     * @param dev
     * @param pinfo a pointer to devinfo_t struct where info will be stored
     * @param errbuf should be large enough to hold error message. PCAP_ERRBUF_SIZE(256) is recommended.
     * @return 0 on success or -1 on failure and error message saved to errbuf
     */
    int get_device_info(const char *dev, devinfo_t *pinfo, char *errbuf);

    /**
     * Fetch ARP cache from system.
     *
     * Returning true doesn't mean that certain hosts are discovered.
     * Caller shouldn't depend on the return value to determine if hosts are discovered and IPs are resolved into MACs.
     *
     * @param map where IPv4s and MACs are to be stored as key-value pairs
     * @return true on success, or false on failure
     */
    bool fetch_cached_arp(arp_map &map);

    /**
     * Query MAC(s) of host(s) in LAN. Privilege is required.
     *
     * Returning true doesn't mean that certain hosts are discovered.
     * Caller shouldn't depend on the return value to determine if hosts are discovered and IPs are resolved into MACs.
     *
     * @param network a c-string indicating a subnet(192.168.43.25/24) or a single host(192.168.43.25)
     * @param map where IPv4s and MACs are to be stored as key-value pairs
     * @return true on success, or false on failure
     */
    bool query_lan_arp(const char *network, arp_map &map);
}
