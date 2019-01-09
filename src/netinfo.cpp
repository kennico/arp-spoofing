//
// Created by kenny on 1/6/19.
//

#include <utility>

#include "hdrs.h"
#include "netinfo.h"
#include "fields.h"


auto fmt_nmap_lan = "nmap -sn %s/%d";
auto grep_ip_mac = R"(grep -oP '(\w{2}:){5}\w{2}|((\d+\.){3}\d+)')";

namespace kni {

    netinfo::netinfo(size_t esize) : buffered_error(esize) {

    }

    bool netinfo::update_arp() {
        auto netmask = *(unsigned int *) &devinfo.ip_netmask;
        netmask = ntohl(netmask);

        char script_line[128];
        sprintf(script_line, fmt_nmap_lan, to_string(devinfo.ip).c_str(), count_bits(netmask));
        sprintf(script_line + strlen(script_line), " | %s", grep_ip_mac);
        LOG_DEBUG("Command: %s", script_line);

        auto fp = popen(script_line, "r");
        if (fp == nullptr) {
            get_syslib_error();
            return false;
        }

        ipmac_map_t tmpmap;
        /*
         * Each line is guaranteed to be less than 128 bytes
         */
        char *buf = script_line;
        size_t bufsize = sizeof(script_line);

        while (true) {
            auto len = getline(&buf, &bufsize, fp);
            std::string ip(buf, static_cast<unsigned long>(len - 1));

            if (len == -1)
                break;

            if (getline(&buf, &bufsize, fp) == -1)
                break;

            mac_t mac;
            assert(mac_pton(buf, &mac));
            tmpmap[ip] = mac;
        }

        ipmac_mapping.clear();  // Discard outdated info
        ipmac_mapping.insert(tmpmap.begin(), tmpmap.end());

        pclose(fp);

        return true;
    }

    bool netinfo::update_gateway() {
        auto ret = get_gateway_ip(devname.c_str());

        if (ret == -1) {
            get_syslib_error();
            return false;
        } else {
            gateway_ip = to_string(*(ipv4_t *) &ret);
            return true;
        }

    }

    bool netinfo::set_dev(const char *dev) {
        if (get_device_info(dev, &devinfo, error_buffer()) != -1) {
            devname = dev;
            return true;
        } else {
            return false;
        }
    }

}