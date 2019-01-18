//
// Created by kenny on 12/29/18.
//

#pragma once

#include <pcap.h>
#include <memory>

#include <sys/socket.h>
#include <linux/if_arp.h>
//#include <linux/if_ether.h>

#include "netinfo.h"
#include "pkt.h"
#include "fields.h"
#include "utils.h"

namespace kni {


    class packet_base {
    public:

        packet_base(u_char *buf, size_t bsize) : buffer(buf), buffer_size(bsize) {

        }

        inline const u_char *content() const noexcept {
            return buffer;
        }

        inline size_t bufsize() const noexcept {
            return buffer_size;
        }

        inline u_char *raw() noexcept {
            return buffer;
        }

    private:
        u_char *buffer{nullptr};
        size_t buffer_size{0};
    };

    class io_packet_base :
            public packet_base,
            public buffered_error {

    public:

//        io_packet_base(u_char* buf, size_t bsize)
//                : packet_base(buf, bsize),
//                  buffered_error(new char[PCAP_BUF_SIZE], PCAP_BUF_SIZE) {
//
//        }
        /**
         * Avoid memory management
         *
         * @param buf
         * @param size
         * @param ebuf
         * @param esize
         */
        io_packet_base(u_char *buf, size_t size, char *ebuf, size_t esize)
                : packet_base(buf, size),
                  buffered_error(ebuf, esize) {

        }

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

        inline bool send_packet(int pktsize) {
            int ret = pcap_sendpacket(handle, content(), pktsize);
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

    class arp_io_packet : public io_packet_base {
    public:
        arp_io_packet(u_char *buf, size_t size, char *ebuf, size_t esize)
                : io_packet_base(buf, size, ebuf, esize),
                  ethHdr(raw()),
                  arpHdr(raw() + ETHER_HDRLEN) {

            arpHdr.htype = ARPHRD_ETHER;
            arpHdr.ptype = ETH_P_IP;
            arpHdr.hlen = 6;
            arpHdr.plen = 4;

            ethHdr.type = ETH_P_ARP;
        }

        template<size_t size, size_t esize>
        arp_io_packet(u_char (&buf)[size], char (&ebuf)[esize]) : arp_io_packet(buf, size, ebuf, esize) {

        }

        /**
         *
         * @param sender_ip sender's protocol(ip) address
         * @param sender_mac sender's hardware address
         * @param target_ip target's protocol(ip) address
         * @param target_mac target's hardware address
         * @return
         */
        inline bool reply(const std::string &sender_ip, const mac_t &sender_mac, const std::string &target_ip,
                          const mac_t &target_mac) {
            arpHdr.spa = sender_ip;
            arpHdr.sha = sender_mac;
            arpHdr.tpa = target_ip;
            arpHdr.tha = target_mac;
            arpHdr.oper = ARPOP_REPLY;

            ethHdr.src = sender_mac;
            ethHdr.dst = target_mac;

            return send_packet(ETHER_HDRLEN + ARP_HDRLEN);
        }

    private:
        modifyhdr_ether ethHdr;
        modifyhdr_arp arpHdr;

    };

}
