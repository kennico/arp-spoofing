//
// Created by kenny on 1/4/19.
//

#pragma once

#include <map>
#include <cstring>

#include "pkt.h"
#include "utils.h"
#include "fields.h"

namespace kni {


    /**
     *
     * @param dev device name
     * @param attempts
     * @param ms time interval between two attempts
     * @return
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

    class netinfo : public buffered_error {
    public:

        netinfo(char *errbuf, size_t errbufsize) : buffered_error(errbuf, errbufsize) {

        }

        /**
         * Obtain device's info
         *
         * @param dev device name
         * @return
         */
        bool set_dev(const char *dev);

        bool update_arp();

        bool update_gateway_ip();


        inline bool cached(const std::string &ip) const noexcept {
            return ipmac_mapping.count(ip) > 0;
        }

        inline const ipmac_map_t &mapping() const noexcept {
            return ipmac_mapping;
        }

        inline const mac_t &map(const std::string &ip) const {
            return ipmac_mapping.at(ip);
        }

    public:
        devinfo_t devinfo{};
        std::string gateway_ip{};
        std::string devname{};
        mac_t gateway_mac{};

    private:

        ipmac_map_t ipmac_mapping{};

    };

    int get_device_info(const char *devname, devinfo_t *pinfo, char *errbuf);
}
