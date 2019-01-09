//
// Created by kenny on 12/29/18.
//

#pragma once

#include <pcap.h>

#include "netinfo.h"
#include "pkt.h"

namespace kni {

    class fake_ether_hdr;

    class fake_arp_hdr;

    class arp_packet_base {
    public:
//    arp_packet_base();
        explicit arp_packet_base(size_t);

        arp_packet_base(u_char *, size_t);

//    void buffer(size_t size);
//    void buffer(u_char* sndbuf, size_t sndsize);
//    template <size_t sndsize>
//    void buffer(u_char(&sndbuf)[sndsize]);

        virtual ~arp_packet_base();

        virtual void construct_packets();

        virtual void apply_default_values() = 0;

        inline size_t bufsize() const noexcept {
            return sndbufsize;
        }

        inline const u_char *buffer() const noexcept {
            return sndbuf;
        }

    protected:
        fake_ether_hdr *hdr_ether{nullptr};
        fake_arp_hdr *hdr_arp{nullptr};

    private:

        u_char *sndbuf{nullptr};
        size_t sndbufsize{0};
        bool allocbuf{true};
    };

    class arp_attack :
            public arp_packet_base,
            public buffered_error {
    public:
        arp_attack(netinfo *, size_t, size_t errsize = PCAP_ERRBUF_SIZE);

        arp_attack(netinfo *, u_char *, size_t, size_t errsize = PCAP_ERRBUF_SIZE);

        ~arp_attack() override;

        void set_fake_ip(const std::string &);

        void set_fake_ip(ipv4_t ipv4);

        bool fake_reply_to(const std::string &);

        bool spoof(const std::string &, const std::string &);

        bool fake_bcast();

        bool open();

        void apply_default_values() override;


    protected:

        pcap_t *handle{nullptr};
        netinfo *netdb{nullptr};
    };
}
