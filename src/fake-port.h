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
            assert(f < s && f > 0 && s < 0x10000);
        }

        /**
         * When SYN or RST is set
         *
         * @param p
         */
        inline void free(port_t p) noexcept {
            if (timestamps.has_key(p)) {
                timestamps.erase_key(p);
                free_que.push(p);
            }
        }

        /**
         * Allocate a port
         *
         * @return nport on failure indicating the exhaustion of fake ports
         */
        inline port_t alloc() noexcept {
            port_t ret = nport;
            auto now = time(nullptr);

            if (!free_que.empty()) {
                ret = free_que.front();
                free_que.pop();

            } else if (from != stop) {
                ret = static_cast<port_t>(from++);

            } else {
                assert(!timestamps.empty());

                auto ite = std::min_element(timestamps.r().begin(), timestamps.r().end());
                auto old_tm = ite->first;
                auto &ports = ite->second;

                if (now - old_tm >= timeout) {
                    // If the selected ports are outdated
                    // Add the outdated ports to free_que

                    // The smallest one comes first
                    for (auto beg = ++ports.begin(); beg != ports.end(); ++beg)
                        free_que.push(*beg);

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
         * TODO Necessary to return a value?
         *
         * Refresh the timestamp of the given port
         *
         * @param p
         * @return false if the port is not in used.
         */
        inline bool refresh(port_t p) noexcept {
            if (timestamps.has_key(p)) {
                auto old = timestamps.map(p);
                auto now = time(nullptr);

                if (now - old < timeout) {
                    timestamps.map(p, now);
                    return true;
                }

                timestamps.erase_key(p);
                free_que.push(p);
            }

            return false;
        }


    private:

        uint32_t from, stop;
        time_t timeout;

        std::queue<port_t> free_que;
        kni::reverse_map<port_t, time_t> timestamps;
    };
}