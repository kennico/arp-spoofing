//
// Created by kenny on 1/6/19.
//

#pragma once

#include <cassert>
#include <list>
#include <arpa/inet.h>

#include "pkt.h"

namespace kni {

    class modifyfld_base {
    public:

        inline const u_char *data() const noexcept {
            return from_ptr;
        }

    protected:
        u_char *from_ptr;
    };

    class hdr_builder {
    public:

        explicit hdr_builder(u_char *buf_) : buf(buf_) {

        }

        template<typename Field>
        inline hdr_builder &operator()(Field &field) noexcept {
            field.accept_from(*this);

            buf += step_bytes;
            buf += step_bits / 8;

            step_bytes = 0;
            step_bits %= 8;

            return *this;
        }

        inline u_char *buffer() noexcept {
            return buf;
        }

    private:
        u_char *buf{nullptr};

    public:
        size_t step_bits{0}, step_bytes{0};
    };

    template<typename network_type>
    class modifybytes : public modifyfld_base {
    public:

        inline constexpr size_t bytes() const noexcept {
            return sizeof(network_type);
        }

        inline void accept_from(hdr_builder &builder) noexcept {
            assert(builder.step_bits == 0);

            from_ptr = builder.buffer();
            builder.step_bytes += bytes();
        }
    };


    template<size_t nbytes>
    struct padding_bytes_traits;

    template<>
    struct padding_bytes_traits<1> {
        using padding_type = uint8_t;

        inline static padding_type hton(padding_type v) noexcept {
            return v;
        }
    };

    template<>
    struct padding_bytes_traits<2> {
        using padding_type = uint16_t;

        inline static padding_type hton(padding_type v) noexcept {
            return htons(v);
        }
    };

    template<>
    struct padding_bytes_traits<3> {
        using padding_type = uint32_t;

        inline static padding_type hton(padding_type v) noexcept {
            return htonl(v);
        }
    };

    template<>
    struct padding_bytes_traits<4> {
        using padding_type = uint32_t;

        inline static padding_type hton(padding_type v) noexcept {
            return htonl(v);
        }
    };

    /**
     *
     * @tparam nbits (0, 32]
     * @tparam padding_traits provides a type named padding_type
     */
    template<size_t nbits,
            typename padding_traits = padding_bytes_traits<(nbits - 1) / 8 + 1>>
    class modifybits : public modifyfld_base {

    private:
        const static size_t BITS_MAXLEN = sizeof(uint32_t) * 8;

    public:

        using padding_type = typename padding_traits::padding_type;

        static_assert(std::is_unsigned<padding_type>::value, "unsigned required");
        static_assert(nbits <= BITS_MAXLEN, "Length limit exceeded");
        static_assert(nbits != 0, "Zero length");       // 0 < nbits <= 32


        modifybits() : modifyfld_base() {

        }

        inline constexpr size_t bits() const noexcept {
            return nbits;
        }

        /**
         *
         * @param value aligned to LSB
         * @return
         */
        inline modifybits<nbits, padding_traits> &operator=(padding_type value) noexcept {
            *(padding_type *) from_ptr = (
                    ((*(padding_type *) from_ptr) & n_inv_mask) |
                    padding_traits::hton(value << r_align));

            return *this;
        };

        inline void accept_from(hdr_builder &builder) noexcept {
            from_ptr = builder.buffer();

            off = builder.step_bits;
            assert(off + bits() <= BITS_MAXLEN);
            builder.step_bits += bits();

            // how many bytes does it occupy since from_ptr?
            auto byt = 1 + (off + bits() - 1) / 8;
            assert(byt > 0 && byt < 4);
            assert(sizeof(padding_type) == byt);

            // how many bits should i left-shift the value?
            r_align = byt * 8 - (off + bits());
            assert(r_align < 8);

            auto mask = (padding_type) 0xFFFFFFFF;
            mask = (mask << (r_align + bits())) | ~(mask << r_align);   // NOLINT
            n_inv_mask = padding_traits::hton(mask);
        }

        /*
         * Should i avoid implicit cast?
         */
        inline explicit operator padding_type() const noexcept {
            return ((*(padding_type *) data()) & (~n_inv_mask)) >> r_align;                // NOLINT
        }

    private:

        size_t off{0}, r_align{0};  // How many bits are there from its end to the first 8-bit byte
        padding_type n_inv_mask{};  // Leave zeros for desired bits while ones for surrounding bits

    };

    template<size_t nbits,
            typename padding_traits = padding_bytes_traits<(nbits - 1) / 8 + 1>>
    class modify_flags : public modifybits<nbits, padding_traits> {
    public:
        using padding_type = typename modifybits<nbits, padding_traits>::padding_type;

        inline void set(padding_type flags) {
            modifybits<nbits, padding_traits>::operator=(padding_type() | flags);
        }

        inline bool isset(padding_type flags) {
            return padding_type() & flags;
        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "HidingNonVirtualFunction"

        inline modify_flags<nbits, padding_traits> &operator=(padding_type value) {
            modifybits<nbits, padding_traits>::operator=(value);
            return *this;
        };
#pragma clang diagnostic pop
    };

    struct modify_uchar : public modifybytes<uint8_t> {

        inline modify_uchar &operator=(uint8_t uc) {
            *from_ptr = uc;
            return *this;
        }
    };

    struct modify_ushort : public modifybytes<uint16_t> {
        inline modify_ushort &operator=(uint16_t uh) {
            *(u_short *) from_ptr = htons(uh);
            return *this;
        }
    };

    struct modify_uint : public modifybytes<uint32_t> {
        inline modify_uint &operator=(uint32_t ui) {
            *(u_int *) from_ptr = htonl(ui);
            return *this;
        }
    };

    // TODO should modify_ipv4 derive from modify_uint?
    struct modify_ipv4 : public modifybytes<ipv4_t> {
        inline modify_ipv4 &operator=(ipv4_t addr) {
            *(ipv4_t *) from_ptr = addr;
            return *this;
        }

        inline modify_ipv4 &operator=(const std::string &ip) {
            operator=(ip.c_str());
            return *this;
        }

        inline modify_ipv4 &operator=(const char *ip) {
            assert(inet_pton(AF_INET, ip, from_ptr));
            return *this;
        }
    };

    struct modify_ipv6 : public modifybytes<ipv6_t> {
        inline modify_ipv6 &operator=(const ipv6_t &addr) {
            *(ipv6_t *) from_ptr = addr;
            return *this;
        }

        inline modify_ipv6 &operator=(const std::string &ip) {
            operator=(ip.c_str());
            return *this;
        }

        inline modify_ipv6 &operator=(const char *ip) {
            assert(inet_pton(AF_INET6, ip, from_ptr));
            return *this;
        }
    };

    struct modify_mac : public modifybytes<mac_t> {
        inline modify_mac &operator=(const char *mac) {
            assert(mac_pton(mac, from_ptr));
            return *this;
        }

        inline modify_mac &operator=(const std::string &mac) {
            assert(mac_pton(mac.c_str(), from_ptr));
            return *this;
        }

        inline modify_mac &operator=(const u_char *mac) {
            for (int i = 0; i < 6; ++i)
                from_ptr[i] = mac[i];
            return *this;
        }

        inline modify_mac &operator=(const mac_t &mac) {
            operator=(mac.data);
            return *this;
        }
    };



    class modifyhdr_base {

    public:
        /**
         *
         * @param len the initial length of header
         */
        explicit modifyhdr_base(size_t len) : hdrlen(len) {

        }

        inline size_t length() const noexcept {
            return hdrlen;
        }

    public:

        inline void update(u_char *buf) {
            hdrlen = update_hdr(buf);
        }

    protected:
        /**
         * TODO should there be a set_input(empty buffer) along with update_hdr(existing buffer)
         * Currently reading any header fields after accepting uninitialized buffer leads to UB
         *
         * @param buf
         * @return header length
         */
        virtual size_t update_hdr(u_char *buf) = 0;


        /**
         *
         * @param buf to be interpreted as the header
         * @return an object used to attach fields to buf via its overloaded parenthesis operator
         */
        inline static hdr_builder field_begin(u_char *buf) noexcept {
            return hdr_builder(buf);
        }

    private:
        size_t hdrlen;
    };

    struct modifyhdr_ether : public modifyhdr_base {

        modifyhdr_ether() : modifyhdr_base(ETHER_HDRLEN) {

        }

        modify_mac src{};                   // Source hardware address
        modify_mac dst{};                   // Destination hardware address
        modify_ushort type{};               // Protocol type

    protected:

        size_t update_hdr(u_char *buf) override {
            field_begin(buf)(dst)(src)(type);
            return ETHER_HDRLEN;
        }
    };

    struct modifyhdr_arp : public modifyhdr_base {

        modify_ushort htype{}, ptype{};     // Types of hardware address and protocol address
        modify_uchar hlen{}, plen{};        // Lengths of hardware address and protocol address
        modify_ushort oper{};               // ARP operation
        modify_mac sha{}, tha{};            // Hardware addresses of sender and target
        modify_ipv4 spa{}, tpa{};           // Protocol addresses of sender and target

        modifyhdr_arp() : modifyhdr_base(ARP_HDRLEN) {

        }

    protected:

        size_t update_hdr(u_char *buf) override {
            field_begin(buf)
                    (htype)(ptype)(hlen)(plen)
                    (oper)
                    (sha)(spa)(tha)(tpa);

            return ARP_HDRLEN;
        }

    };

    // IPv4 options are not supported to be modified in this way
    struct modifyhdr_ipv4 : public modifyhdr_base {

        modifybits<4> version{};            // Version
        modifybits<4> ihl{};                // IHL, Internet header length in double-words(4 bytes, 32 bits)
        modify_uchar diff{};                // Differentiated services
        modify_ushort tot_len{}, id{};      // Total length in bytes, and identification
        modify_flags<3> flags{};            // Flags
        modifybits<13> frag_off{};          // Fragment offset
        modify_uchar ttl{}, proto{};        // Time to live and next protocol
        modify_ushort check{};              // Header checksum
        modify_ipv4 src{}, dst{};           // Source address and destination address

        modifyhdr_ipv4() : modifyhdr_base(IPV4_HDRLEN) {

        }

    protected:
        /**
         * TODO what to do with a zero-length ihl?
         *
         * @param buf
         * @return
         */
        size_t update_hdr(u_char *buf) override {
            field_begin(buf)(version)(ihl)(diff)(tot_len)
                    (id)(flags)(frag_off)
                    (ttl)(proto)(check)
                    (src)(dst);

            return static_cast<size_t>((uint8_t) ihl * 4);
        }
    };

//    struct modifyhdr_ipv6 : public modifyhdr_base {
//
//        modifybits<4> version{};
//        modifybits<8> traffic{};
//        modifybits<20> flow{};
//        modify_ushort payload_len{};
//        modify_uchar next{}, hop_lim{};
//        modify_ipv6 src{}, dst{};
//
//        modifyhdr_ipv6() : modifyhdr_base(IPV6_HDRLEN) {
//
//        }
//
//    protected:
//
//        size_t update_hdr(u_char* buf) override {
//            field_begin(buf)(version)(traffic)(flow)
//                    (payload_len)(next)(hop_lim)
//                    (src)(dst);
//
//            static_assert(false, "Not implemented");
//            return IPV6_HDRLEN;
//        }
//    };

    enum tcp_flags {
        FIN = 0x001, SYN = 0x002, RST = 0x004, PSH = 0x008,
        ACK = 0x010, URG = 0x020, ECE = 0x040, CWR = 0x080,
        NCE = 0x100
    };

    // IPv4 options are not supported to be modified in this way
    struct modifyhdr_tcp : public modifyhdr_base {
        modify_ushort src{}, dst{};                     // Source port and destination port
        modify_uint seq{}, ack_seq{};                   // Sequence number and acknowledgement number
        modifybits<4> doff{};                           // Data offset in double-words(4 bytes, 32 bits)
        modify_flags<12> flags{};                       // Reserved bits(3), NS(1) and flags(8)
        modify_ushort window{}, check{}, urg_ptr{};     // Windows size, header checksum and urgent pointer

        modifyhdr_tcp() : modifyhdr_base(TCP_HDRLEN) {

        }

    protected:
        size_t update_hdr(u_char *buf) override {
            field_begin(buf)(src)(dst)
                    (seq)(ack_seq)
                    (doff)(flags)(window)
                    (check)(urg_ptr);

            return static_cast<size_t>((uint8_t) doff * 4);
        }

    };


    class modifypkt_base {
    public:

        virtual void update_input(u_char *buf) {
            buffer = buf;
            for (auto hdr : headers) {
                hdr->update(buf);
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

        modifyhdr_ether ethHdr{};
        modifyhdr_arp arpHdr{};

        modifypkt_arp() {
            add_header(&ethHdr);
            add_header(&arpHdr);
        }

    };

    struct modifypkt_tcp : public modifypkt_base {

        modifyhdr_ether ethHdr{};
        modifyhdr_ipv4 ipHdr{};
        modifyhdr_tcp tcpHdr{};

        modifypkt_tcp() {
            add_header(&ethHdr);
            add_header(&ipHdr);
            add_header(&tcpHdr);
        }

    };

//    struct modifypkt_ip : public modifypkt_base {
//
//    };

}
