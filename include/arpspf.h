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
        /**
         * Avoid memory management
         *
         * @param ebuf
         * @param esize
         */
        io_packet_base(char *ebuf, size_t esize) : buffered_error(ebuf, esize) {

        }

        /**
         * Open a device
         *
         * @param devname
         * @return
         */
        inline bool open(const std::string &devname) {
            handle = pcap_open_live(devname.c_str(), 4096, 1, 0, errbuf());
            return handle != nullptr;
        }

        inline void close() {
            if (handle)
                pcap_close(handle);
            handle = nullptr;
        }


    protected:

        inline bool send_packet(const u_char *content, int pktsize) {
            int ret = pcap_sendpacket(handle, content, pktsize);
            if (ret == PCAP_ERROR) {
                snprintf(errbuf(), errbufsize(), "%s", pcap_geterr(handle));
                return false;
            } else {
                return true;
            }
        }

    private:
        pcap_t *handle{nullptr};
    };


    class arp_io_packet :
            public io_packet_base,
            public arp_packet {
    public:
        arp_io_packet(char *ebuf, size_t esize)
                : io_packet_base(ebuf, esize), arp_packet() {

        }

        template<size_t esize>
        explicit arp_io_packet(char (&ebuf)[esize]) : arp_io_packet(ebuf, esize) {

        }

        void prepare(u_char *buf) {
            arp_packet::update(buf);

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
