//
// Created by kenny on 1/6/19.
//

#pragma once

#include <cassert>
#include <list>
#include <arpa/inet.h>

#include "pkt.h"

namespace kni {

    template<typename network_t>
    class modifyfld_base {
    public:

        inline const u_char *data() const noexcept {
            return from;
        }

        inline constexpr size_t size() const noexcept {
            return sizeof(network_t);
        }

        inline void set_from(u_char *buf) noexcept {
            from = buf;
        }

    protected:
        u_char *from;
    };


    struct modify_uchar : public modifyfld_base<u_char> {

        inline modify_uchar &operator=(u_char ch) {
            *from = ch;
            return *this;
        }
    };

    struct modify_ushort : public modifyfld_base<u_short> {
        inline modify_ushort &operator=(u_short sh) {
            *(u_short *) from = htons(sh);
            return *this;
        }
    };

    struct modify_uint : public modifyfld_base<u_int> {
        inline modify_uint &operator=(u_int ui) {
            *(u_int *) from = htonl(ui);
            return *this;
        }
    };

    struct modify_ipv4 : public modifyfld_base<ipv4_t> {
        inline modify_ipv4 &operator=(ipv4_t addr) {
            *(ipv4_t *) from = addr;
            return *this;
        }

        inline modify_ipv4 &operator=(const std::string &ip) {
            operator=(ip.c_str());
            return *this;
        }

        inline modify_ipv4 &operator=(const char *ip) {
            assert(inet_pton(AF_INET, ip, from));
            return *this;
        }
    };

    struct modify_mac : public modifyfld_base<mac_t> {
        inline modify_mac &operator=(const char *mac) {
            assert(mac_pton(mac, from));
            return *this;
        }

        inline modify_mac &operator=(const std::string &mac) {
            assert(mac_pton(mac.c_str(), from));
            return *this;
        }

        inline modify_mac &operator=(const u_char *mac) {
            for (int i = 0; i < 6; ++i)
                from[i] = mac[i];
            return *this;
        }

        inline modify_mac &operator=(const mac_t &mac) {
            operator=(mac.data);
            return *this;
        }
    };


    class modifyhdr_base {
    private:
        class fields_initializer {
        public:

            explicit fields_initializer(u_char *buf_) : buf(buf_) {

            }

            template<typename Field>
            inline fields_initializer &operator()(Field &field) noexcept {
                field.set_from(buf);
                buf += field.size();
                return *this;
            }

        private:
            u_char *buf{nullptr};
        };

    public:
        explicit modifyhdr_base(size_t len) : hdrlen(len) {

        }

        inline size_t length() const noexcept {
            return hdrlen;
        }

        virtual void set_input(u_char *buf) = 0;

    protected:

        inline static fields_initializer field_begin(u_char *buf) noexcept {
            return fields_initializer(buf);
        }

    protected:
        size_t hdrlen;
    };

    struct modifyhdr_ether : public modifyhdr_base {

        modifyhdr_ether() : modifyhdr_base(ETHER_HDRLEN) {

        }

        void set_input(u_char *buf) override {
            field_begin(buf)(dst)(src)(type);
        }

        modify_mac src{};
        modify_mac dst{};
        modify_ushort type{};
    };

    struct modifyhdr_arp : public modifyhdr_base {

        modify_ushort htype{}, ptype{};
        modify_uchar hlen{}, plen{};
        modify_ushort oper{};
        modify_mac sha{}, tha{};
        modify_ipv4 spa{}, tpa{};

        modifyhdr_arp() : modifyhdr_base(ARP_HDRLEN) {

        }

        void set_input(u_char *buf) override {
            field_begin(buf)
                    (htype)(ptype)(hlen)(plen)
                    (oper)
                    (sha)(spa)(tha)(tpa);
        }

    };

    class modifypkt_base {
    public:

        virtual void set_input(u_char *buf) {
            buffer = buf;
            for (auto hdr : headers) {
                hdr->set_input(buf);
                buf += hdr->length();
            }
        }

        inline const u_char *content() const noexcept {
            return buffer;
        }

        inline u_char *raw() noexcept {
            return buffer;
        }

    protected:
        void add_header(modifyhdr_base *pkt) {
            headers.push_back(pkt);
        }

    private:

        std::list<modifyhdr_base *> headers{};
        u_char *buffer{nullptr};

    };

    struct modifypkt_arp : public modifypkt_base {

        modifyhdr_ether ethHdr;
        modifyhdr_arp arpHdr;

        modifypkt_arp() : ethHdr(), arpHdr() {
            add_header(&ethHdr);
            add_header(&arpHdr);
        }

    };

//    struct modifypkt_ip : public modifypkt_base {
//
//    };

}
