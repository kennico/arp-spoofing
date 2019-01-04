//
// Created by kenny on 12/29/18.
//

#pragma once

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cassert>
#include <string>

#include "netinfo.h"
#include "pkt.h"



void fatal_error(const char* src, const char* err);


std::string to_string(const ipv4_t&);
std::string to_string(const ipv6_t&);
std::string to_string(const mac_t&);

std::string get_address_string(const sockaddr *paddr);


template <typename net_type>
class modify_field_base {
public:

    inline void set_assign_from(u_char*& buf) {
        from = buf;
        buf += sizeof(net_type);
    }

    inline const u_char* data() const noexcept {
        return from;
    }

protected:
    u_char * from;
};

//template <size_t N>
//class modify_multibytes_base {
//public:
//
//    inline void set_assign_from(u_char*& buf) {
//        from = buf;
//        buf += N;
//    }
//
//protected:
//    u_char * from;
//};

struct modify_uchar:public modify_field_base<u_char> {

    inline modify_uchar&operator=(u_char ch) {
        *from = ch;
        return *this;
    }
};

struct modify_ushort:public modify_field_base<u_short> {
    inline modify_ushort&operator=(u_short sh) {
        *(u_short*)from = htons(sh);
        return *this;
    }
};

struct modify_uint:public modify_field_base<u_int> {
    inline modify_uint&operator=(u_int ui) {
        *(u_int*)from = htonl(ui);
        return *this;
    }
};

struct modify_ipv4:public modify_field_base<ipv4_t> {
    inline modify_ipv4&operator=(ipv4_t addr) {
        *(ipv4_t*)from = addr;
        return *this;
    }

    inline modify_ipv4&operator=(const std::string &ip) {
        operator=(ip.c_str());
        return *this;
    }

    inline modify_ipv4&operator=(const char* ip) {
        assert(inet_pton(AF_INET, ip, from));
        return *this;
    }
};

struct modify_mac: public modify_field_base<mac_t> {
    inline modify_mac&operator=(const char* mac) {
        assert(mac_pton(mac, from));
        return *this;
    }

    inline modify_mac&operator=(const u_char* mac) {
        for (int i = 0; i < 6; ++i)
            from[i] = mac[i];
        return *this;
    }
};

template <size_t header_len>
class fake_pkt_base {
public:

    fake_pkt_base(u_char* buf, size_t bufsize) : pkt(buf), from(buf) {
        assert(bufsize >= bytes());
    }

    inline const u_char * packet() const noexcept {
        return pkt;
    }

    inline const u_char * end() const noexcept {
        return pkt + bytes();
    }

    inline constexpr size_t bytes() const noexcept {
        return header_len;
    }

protected:

    template <typename modify_field>
    void set_assign_to(modify_field &field) {
        field.set_assign_from(from);
    }

private:

    u_char * from{nullptr};
    u_char * pkt{nullptr};
};

struct fake_ether_hdr : public fake_pkt_base<ETHER_HDR_LEN> {

    modify_mac      src{};
    modify_mac      dst{};
    modify_ushort   type{};

    fake_ether_hdr(u_char *buf, size_t bufsize): fake_pkt_base(buf, bufsize) {
        set_assign_to(dst);
        set_assign_to(src);
        set_assign_to(type);
    }


};

struct fake_arp_hdr: public fake_pkt_base<ARP_HDR_LEN> {

    modify_ushort   htype{};
    modify_ushort   ptype{};
    modify_uchar    hlen{};
    modify_uchar    plen{};
    modify_ushort   oper{};
    modify_mac      sha{};
    modify_ipv4     spa{};
    modify_mac      tha{};
    modify_ipv4     tpa{};

    fake_arp_hdr(u_char* buf, size_t bufsize): fake_pkt_base(buf, bufsize) {
        set_assign_to(htype);
        set_assign_to(ptype);

        set_assign_to(hlen);
        set_assign_to(plen);
        set_assign_to(oper);

        set_assign_to(sha);
        set_assign_to(spa);
        set_assign_to(tha);
        set_assign_to(tpa);
    }

};

//class fake_object {
//    void set_buffer() {
//
//    }
//
//    void send_fake_pkt(std::string victim) {
//
//    }
//};
//
//class arpspf_device {
//
//    arpspf_device(/*dev_name, dev_mac*/) {
//
//    }
//
//    void get_mapping();
//
//    /**/ void disguise_as(std::string ip);
//
//    void disguise_gateway(std::string victim_ip, std::string victim_mac) {
//
//    }
//    void disguise_victim(std::string victim_ip, std::string victim_mac) {
//
//    }
//};