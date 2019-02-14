//
// Created by kenny on 1/6/19.
//

#include "hdrs.h"
#include "utils.h"
#include "lan_info.h"

namespace kni {

    bool lan_info::fetch_arp() {
        char line_buf[128] = "arp -n | "
                             R"(grep -oP '(\w{2}:){5}\w{2}|((\d+\.){3}\d+)')";
        KNI_LOG_DEBUG("Command: %s", line_buf);

        auto fp = popen(line_buf, "r");
        if (fp == nullptr) {
            getsyserr();
            return false;
        }

        ipmac_map_t tmpmap;

        char *buf = line_buf;
        size_t bufsize = sizeof(line_buf);

        while (true) {
            auto len = getline(&buf, &bufsize, fp);
            std::string ip(line_buf, static_cast<unsigned long>(len - 1));

            if (len == -1 || getline(&buf, &bufsize, fp) == -1)
                break;

            mac_t mac;
            assert(mac_pton(buf, &mac));
            tmpmap[ip] = mac;
        }

        gateway_mac = tmpmap[gateway_ip];
        ipmac_mapping = std::move(tmpmap);

        pclose(fp);

        return true;
    }

    /**
     *
     * cat /proc/net/route gives output like:
     * Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
    wlx502b73dc543f	00000000	012BA8C0	0003	0	0	600	00000000	0	0	0
    wlx502b73dc543f	0000FEA9	00000000	0001	0	0	1000	0000FFFF	0	0	0
    wlx502b73dc543f	002BA8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
     *
     * @return
     */
    bool lan_info::update_gateway_ip() {
        auto ret = get_gateway_ip(devname.c_str());

        if (ret == -1) {
            getsyserr();
            return false;
        } else {
            gateway_ip = to_string(*(ipv4_t *) &ret);
            return true;
        }

    }

    bool lan_info::set_dev(const char *name) {
        if (get_device_info(name, &dev, err()) != -1) {
            devname = name;
            return true;
        } else {
            return false;
        }
    }

}