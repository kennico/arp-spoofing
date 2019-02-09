//
// Created by kenny on 2/7/19.
//

#pragma once

#include "arpspf.h"
#include "pth-args.h"
#include "hdrs.h"

namespace kni {

    class fake_port_manager {
    public:
        constexpr static port_t nport = 0;

        /**
         *
         * @param f
         * @param t in seconds inferred from its type
         */
        explicit fake_port_manager(uint32_t f = 1024, uint32_t s = 0x10000, time_t t = 5) :
                from(f), stop(s), timeout(t) {
            assert(f < s && s < 0x10000);
        }

        /**
         * When SYN or RST is set
         *
         * @param port
         * @return true if port is actually released
         */
        inline bool free(port_t port) noexcept {
            if (timestamps.has_key(port)) {
                timestamps.erase_key(port);
                recycle.push(port);
                return true;
            }
            return false;
        }

        /**
         * Allocate a port
         *
         * @return nport on failure
         */
        inline port_t alloc() noexcept {
            port_t ret = nport;
            auto now = time(nullptr);

            if (!recycle.empty()) {
                ret = recycle.front();
                recycle.pop();

            } else if (from != stop) {
                ret = static_cast<port_t>(from++);

            } else {
                assert(!timestamps.empty());

                auto ite = std::min_element(timestamps.r().begin(), timestamps.r().end());
                auto old_tm = ite->first;
                auto &ports = ite->second;

                if (now - old_tm >= timeout) {
                    // If the selected ports are outdated
                    // Add the outdated ports to recycle bin

                    // The smallest one comes first
                    for (auto beg = ++ports.begin(); beg != ports.end(); ++beg)
                        recycle.push(*beg);

                    ret = *(std::min_element(ports.begin(), ports.end()));
                    // Remove the outdated ports
                    timestamps.erase_value(old_tm);
                }
            }

            if (ret != nport)
                timestamps.map(ret, now);

            return ret;
        }

        /**
         * Refresh the timestamp of the given port
         * @param p
         */
        inline void refresh(port_t p) noexcept {
            assert(timestamps.has_key(p));

            timestamps.erase_key(p);
            auto map_succ = timestamps.map(p, time(nullptr));
            assert(map_succ);
        }

#ifndef KNI_DEBUG
        private:
#endif
        uint32_t from, stop;
        time_t timeout;

        std::queue<port_t> recycle;
        kni::reverse_map<port_t, time_t> timestamps;
    };
}