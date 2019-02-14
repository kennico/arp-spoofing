//
// Created by kenny on 1/4/19.
//

#pragma once

#include <map>
#include <cstring>

#include "pkt.h"
#include "utils.h"

namespace kni {


    /**
     *
     * @param dev device name
     * @param attempts
     * @param ms time interval between two attempts
     * @return an ip address in network byte order if success; else -1 on failure and error info can be retrieved via errno
     */
    int get_gateway_ip(const char *dev = nullptr, int attempts = 5, int ms = 50);

    struct devinfo_t {
        mac_t hw_addr{};        // Hardware address
        mac_t hw_bcast{};       // Broadcast hardware address
        ipv4_t ip{};            // IPv4 address
        ipv4_t ip_bcast{};      // Broadcast IPv4 address
        ipv4_t ip_netmask{};    // Subnet mask
    };

    using ipmac_map_t = std::map<std::string, mac_t>;

    /**
     * TODO Discover hosts and obtain ARP information
     */
    class lan_info : public pcap_error {
    public:

        /**
         * Obtain device's info
         *
         * @param dev device name
         * @return
         */
        bool set_dev(const char *dev);

        bool fetch_arp();

        bool update_gateway_ip();

        inline bool is_cached(const std::string &ip) const noexcept {
            return ipmac_mapping.count(ip) > 0;
        }

        inline const ipmac_map_t &mapping() const noexcept {
            return ipmac_mapping;
        }

        /**
         * Map an IPv4 string to an MAC address
         *
         * @param ip
         * @return the MAC address of gateway if such ip has not been discovered yet
         */
        inline const mac_t &map(const std::string &ip) const {
            auto find = ipmac_mapping.find(ip);
            if (find == ipmac_mapping.end())
                return gateway_mac;
            else
                return find->second;
        }

    public:
        std::string gateway_ip{};
        mac_t gateway_mac{};
        devinfo_t dev{};
        std::string devname{};
#ifndef KNI_DEBUG_TEST_PREVENT_SEND
    protected:
#endif
        ipmac_map_t ipmac_mapping{};

    };

    /**
     *
     * @param devname
     * @param pinfo a pointer to devinfo_t struct where info will be stored
     * @param errbuf
     * @return
     */
    int get_device_info(const char *devname, devinfo_t *pinfo, char *errbuf);
}
