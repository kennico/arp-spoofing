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
#include "lan_info.h"
#include "nethdrs.h"

namespace kni {


    class io_packet_base : public pcap_error {

    public:

        /**
         * Open a device
         *
         * @param devname
         * @return
         */
        inline bool open(const char *devname) {
            handle = pcap_open_live(devname, snap_len, 1, 0, err());
            return handle != nullptr;
        }

        /**
         * Check if the handle is null before closing it
         */
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
                    snprintf(err(), errbufsize(), "%s", pcap_geterr(handle));
                    return false;
                }
                handle_packet();
                cap_packet = nullptr;
            }

            return true;
        }

        virtual void loop_break() noexcept {
            keep_loop = false;
        }

#ifndef KNI_DEBUG
    protected:
#endif

        virtual void handle_packet() {

        }

        /**
         *
         * @param content
         * @param pktsize
         * @return false indicating an error which can be retrieved via error()
         */
        inline bool send_packet(const u_char *content, int pktsize) {
            int ret = pcap_sendpacket(handle, content, pktsize);
            if (ret == PCAP_ERROR) {
                snprintf(err(), errbufsize(), "%s", pcap_geterr(handle));
                return false;
            } else {
                return true;
            }
        }

#ifndef KNI_DEBUG_TEST_PREVENT_SEND
    protected:
#endif
        bool keep_loop{true};
        int snap_len{2048};
        const u_char *cap_packet{nullptr};
        pcap_pkthdr cap_info{};

    private:
        pcap_t *handle{nullptr};

    };

    class io_packet_buf : public io_packet_base {
    public:
        explicit io_packet_buf(size_t bufsize) :
                io_packet_base(), send_buf(new u_char[bufsize]), send_bufsize(bufsize) {

        }

    protected:
        std::unique_ptr<u_char[]> send_buf;
        size_t send_bufsize;
    };

    class arp_io_packet : public io_packet_buf, public arp_packet {
    public:

        arp_io_packet() : io_packet_buf(ETHER_HDRLEN + ARP_HDRLEN), arp_packet() {
            setter set(send_buf.get());
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
            setter set(send_buf.get());
            set(ethHdr.src, sender_mac);
            set(ethHdr.dst, target_mac);

            set.incr(ETHER_HDRLEN);
            set(arpHdr.spa, sender_ip);
            set(arpHdr.sha, sender_mac);
            set(arpHdr.tpa, target_ip);
            set(arpHdr.tha, target_mac);
            set(arpHdr.oper, ARPOP_REPLY);

            return send_packet(send_buf.get(), ETHER_HDRLEN + ARP_HDRLEN);
        }

    };
}
