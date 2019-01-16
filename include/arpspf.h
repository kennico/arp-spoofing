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

        explicit packet_base(size_t buffersize) : mem(new u_char[buffersize]), memlen(buffersize) {

        }

        inline const u_char *content() const noexcept {
            return mem.get();
        }

        inline size_t bufsize() const noexcept {
            return memlen;
        }

    protected:

        inline u_char *raw() noexcept {
            return mem.get();
        }

    private:
        std::unique_ptr<u_char[]> mem{};
        size_t memlen{0};
    };

    class demo_arp_packet : public packet_base {
    public:
        demo_arp_packet()
                : packet_base(ETHER_HDR_LEN + ARP_HDR_LEN),
                  ethHdr(raw()),
                  arpHdr(raw() + ETHER_HDR_LEN) {

            arpHdr.htype = ARPHRD_ETHER;
            arpHdr.ptype = ETH_P_IP;
            arpHdr.hlen = 6;
            arpHdr.plen = 4;

            ethHdr.type = ETH_P_ARP;
        }

    protected:
        modifyhdr_ether ethHdr;
        modifyhdr_arp arpHdr;
    };

    class io_packet_base :
            public packet_base,
            public buffered_error {

    public:

        io_packet_base(size_t bufsize, char *ebuf, size_t esize)
                : packet_base(bufsize),
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
        arp_io_packet(char *ebuf, size_t esize)
                : io_packet_base(ETHER_HDR_LEN + ARP_HDR_LEN, ebuf, esize),
                  ethHdr(raw()),
                  arpHdr(raw() + ETHER_HDR_LEN) {

            arpHdr.htype = ARPHRD_ETHER;
            arpHdr.ptype = ETH_P_IP;
            arpHdr.hlen = 6;
            arpHdr.plen = 4;

            ethHdr.type = ETH_P_ARP;
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

            return send_packet(ETHER_HDR_LEN + ARP_HDR_LEN);
        }

    private:
        modifyhdr_ether ethHdr;
        modifyhdr_arp arpHdr;

    };

}
