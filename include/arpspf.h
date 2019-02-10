//
// Created by kenny on 12/29/18.
//

#pragma once

#include <pcap.h>
#include <memory>

#include <sys/socket.h>
#include <linux/if_arp.h>

#include "pkt.h"
#include "utils.h"
#include "netinfo.h"
#include "nethdrs.h"

namespace kni {


    class io_packet_base : public buffered_error {

    public:

        io_packet_base() : buffered_error(), mem_err(new char[PCAP_ERRBUF_SIZE]) {
            set_buf(mem_err.get(), PCAP_ERRBUF_SIZE);
        }

        /**
         * Open a device
         *
         * @param devname
         * @return
         */
        inline bool open(const std::string &devname) {
            handle = pcap_open_live(devname.c_str(), snap_len, 1, 0, errbuf());
            return handle != nullptr;
        }

        inline void close() {
            if (handle)
                pcap_close(handle);
            handle = nullptr;
        }

        /**
         *
         * @return false indicating an error
         */
        inline bool loop_packets() noexcept {
            while (keep_loop) {
                cap_packet = pcap_next(handle, &cap_info);
                if (cap_packet == nullptr) {
                    snprintf(errbuf(), errbufsize(), "%s", pcap_geterr(handle));
                    return false;
                }
                handle_packet();
            }

            return true;
        }

        virtual void loop_break() noexcept {
            keep_loop = false;
        }

    protected:

        virtual void handle_packet() {}

        /**
         *
         * @param content
         * @param pktsize
         * @return false indicating an error which can be retrieved via error()
         */
        inline bool send_packet(const u_char *content, int pktsize) {
            int ret = pcap_sendpacket(handle, content, pktsize);
            if (ret == PCAP_ERROR) {
                snprintf(errbuf(), errbufsize(), "%s", pcap_geterr(handle));
                return false;
            } else {
                return true;
            }
        }

    protected:
        bool keep_loop{true};
        int snap_len{2048};
        const u_char *cap_packet{nullptr};
        pcap_pkthdr cap_info{};

    private:
        pcap_t *handle{nullptr};
        std::unique_ptr<char[]> mem_err;

    };


    class arp_io_packet : public io_packet_base, public arp_packet {
    public:

        void prepare(u_char *buf) {
            this->buf = buf;

            setter set(buf);
            set(ethHdr.type, ETH_P_ARP);

            set.incr(ETHER_HDRLEN);
            set(arpHdr.htype, ARPHRD_ETHER);
            set(arpHdr.ptype, ETH_P_IP);
            set(arpHdr.hlen, 6);
            set(arpHdr.plen, 4);
        }

        /**
         * Send an ARP reply
         *
         * TODO bcast() for ARP broadcast
         *
         * @param sender_ip sender's protocol(ip) address
         * @param sender_mac sender's hardware address
         * @param target_ip target's protocol(ip) address
         * @param target_mac target's hardware address
         * @return
         */
        inline bool reply(const std::string &sender_ip, const mac_t &sender_mac, const std::string &target_ip,
                          const mac_t &target_mac) {
            setter set(buf);
            set(ethHdr.src, sender_mac);
            set(ethHdr.dst, target_mac);

            set.incr(ETHER_HDRLEN);
            set(arpHdr.spa, sender_ip);
            set(arpHdr.sha, sender_mac);
            set(arpHdr.tpa, target_ip);
            set(arpHdr.tha, target_mac);
            set(arpHdr.oper, ARPOP_REPLY);

            return send_packet(buf, ETHER_HDRLEN + ARP_HDRLEN);
        }

    private:

        u_char *buf{nullptr};

    };
}
