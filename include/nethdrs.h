//
// Created by kenny on 2/4/19.
//

#pragma once

#include <list>

#include <cstdlib>
#include <cstdint>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pkt.h"
#include "utils.h"

namespace kni {
    /*
     * setter set(buf);
     *
     * set(header.ipv4, "192.168.225.1");
     * set(header.mac, "11:11:22:22:33:33");
     * set(header.port, 443);
     * set(header.port, lambda);
     *
     *
     * std::cout << read(header.ipv4) << std::endl;
     *
     */

    template<typename N>
    class field_bytes_base {
    public:
        using bytes_type    = N;
        using host_type     = N;

        inline constexpr size_t bytes() const noexcept {
            return sizeof(bytes_type);
        }

        /**
         *
         * @return length in bits
         */
        inline constexpr size_t bits_len() const noexcept {
            return bytes() << 3;    // NOLINT
        }

        inline size_t off() const noexcept {
            return offset;
        }

        inline void off(size_t offset) noexcept {
            this->offset = offset;
        }

    private:

        size_t offset{0};
    };

    template<typename network_type>
    struct endianness;

    template<>
    struct endianness<uint8_t> {
        using bytes_type = uint8_t;

        inline static bytes_type hton(bytes_type hostchar) noexcept {
            return hostchar;
        }

        inline static bytes_type ntoh(bytes_type netchar) noexcept {
            return netchar;
        }
    };

    template<>
    struct endianness<uint16_t> {
        using bytes_type = uint16_t;

        inline static bytes_type hton(bytes_type hostshort) noexcept {
            return htons(hostshort);
        }

        inline static bytes_type ntoh(bytes_type netshort) noexcept {
            return ntohs(netshort);
        }
    };

    template<>
    struct endianness<uint32_t> {
        using bytes_type = uint32_t;

        inline static bytes_type hton(bytes_type hostlong) noexcept {
            return htonl(hostlong);
        }

        inline static bytes_type ntoh(bytes_type netlong) noexcept {
            return ntohl(netlong);
        }
    };

    template<typename N>
    class field_unsigned : public field_bytes_base<N> {
    };

    template<size_t nbits>
    struct alignment {
        constexpr const static size_t bytes = ((nbits - 1) >> 3) + 1; // NOLINT
    };

    template<size_t nbytes>
    struct align_bytes;

    template<>
    struct align_bytes<1> {
        using aligned_type = uint8_t;
    };

    template<>
    struct align_bytes<2> {
        using aligned_type = uint16_t;
    };

    template<>
    struct align_bytes<3> {
        using aligned_type = uint32_t;
    };

    template<>
    struct align_bytes<4> {
        using aligned_type = uint32_t;
    };

    template<size_t N, size_t B = alignment<N>::bytes>
    class field_bits {
    public:

        constexpr static size_t MAX_BITS = sizeof(uint32_t) * 4;

        using aligned_type  = typename align_bytes<B>::aligned_type;
        using endian_type   = endianness<aligned_type>;
        using host_type     = aligned_type;
        using bytes_type    = aligned_type;

        static_assert(N <= MAX_BITS, "length limit exceeded");
        static_assert(N != 0, "zero length");
        static_assert(std::is_unsigned<aligned_type>::value, "unsigned required");

        inline constexpr size_t bits_len() const noexcept {
            return N;
        }

        /**
         *
         * @param offset in bits
         */
        inline void off(size_t offset) noexcept {
            this->offset = offset;

            auto byt_off = offset % 8;
            assert(byt_off + bits_len() <= MAX_BITS);

            auto byt = 1 + (byt_off + bits_len() - 1) / 8; // How many bytes does it occupy since from_ptr?
            assert(byt > 0 && byt < 4);
            assert(sizeof(aligned_type) == byt);

            r_padding_count = byt * 8 - (byt_off + bits_len()); // How many bits should I left-shift the value?

            auto mask = (aligned_type) 0xFFFFFFFF;
            mask = (mask << (r_padding_count + bits_len())) | ~(mask << r_padding_count);   // NOLINT
            net_invert_mask = endian_type::hton(mask);
        }

        /**
         *
         * @return offset in bits
         */
        inline size_t off() const noexcept {
            return offset;
        }

    public:
        size_t offset{};
        size_t r_padding_count{};           // How many bits are there from its end to the first 8-bit byte
        aligned_type net_invert_mask{};     // Zeros for desired bits while ones for surrounding data bits in network order

    };

    /*
     * https://stackoverflow.com/a/15039190/8706476
     *
     * uintX_t is guaranteed to an integer type with width X
     */
    using field_byte = field_unsigned<uint8_t>;
    using field_word = field_unsigned<uint16_t>;
    using field_dword= field_unsigned<uint32_t>;

    using field_ipv4 = field_bytes_base<ipv4_t>;
    using field_mac  = field_bytes_base<mac_t>;

    template<typename F>
    struct field_functor;

    template<typename T>
    struct field_functor<field_unsigned<T>> {
        using endian_type   = endianness<T>;
        using unsigned_type = typename endian_type::bytes_type;

        inline void operator()(void *b, const field_unsigned<T> &, unsigned_type u) const {
            *(unsigned_type *) b = endian_type::hton(u);
        }

        inline unsigned_type operator()(const void *b, const field_unsigned<T> &) const {
            return endian_type::ntoh(*(unsigned_type *) b);
        }
    };

    template<size_t N>
    struct field_functor<field_bits<N>> {
        using aligned_type  = typename field_bits<N>::aligned_type;
        using endian_type   = endianness<aligned_type>;

        inline void operator()(void *b, const field_bits<N> &f, aligned_type u) const {
            *(aligned_type *) (b) =
                    (*(aligned_type *) (b)) & f.net_invert_mask |
                    endian_type::hton(u << f.r_padding_count);                          // NOLINT
        }

        inline aligned_type operator()(const void *b, const field_bits<N> &f) const {
            return endian_type::ntoh((*(aligned_type *) b & (~f.net_invert_mask)) >> f.r_padding_count);   // NOLINT
        }
    };

    template<>
    struct field_functor<field_ipv4> {

        inline void operator()(void *b, const field_ipv4 &, ipv4_t h) const {
            *(ipv4_t *) b = h;
        }

        inline void operator()(void *b, const field_ipv4 &, const char *ip) const {
            assert(inet_pton(AF_INET, ip, b));
        }

        inline void operator()(void *b, const field_ipv4 &arg, const std::string &ip) const {
            this->operator()(b, arg, ip.c_str());
        }

        inline ipv4_t operator()(const void *b, const field_ipv4 &) const {
            return *(ipv4_t *) b;
        }
    };

    template<>
    struct field_functor<field_mac> {

        inline void operator()(void *b, const field_mac &, const char *mac) {
            assert(mac_pton(mac, b));
        }

        inline void operator()(void *b, const field_mac &, const std::string &mac) {
            assert(mac_pton(mac.c_str(), b));
        }

        inline void operator()(void *b, const field_mac &, const void *mac) {
            assert(memcpy(b, mac, 6));
        }

        inline void operator()(void *b, const field_mac &arg, const mac_t &mac) {
            this->operator()(b, arg, mac.data);
        }

        inline mac_t operator()(const void *b, const field_mac &) const {
            return *(mac_t *) b;
        }
    };


    class base_header {
    protected:
        /**
         * TODO A constructor accepting initial offset?
         *
         * Called in derived constructor.
         */
        class concatenate {
        public:

            constexpr explicit concatenate(size_t off = 0) : acc_len(off) {

            }

            template<typename field_type>
            inline concatenate &operator()(field_type &f) {
                f.off(acc_len);
                acc_len += f.bits_len();
                return *this;
            }

        public:

            size_t acc_len; // Measured in bits.

        };

    public:

        constexpr explicit base_header(size_t init_len) : hdrlen(init_len) {

        }

        /**
         *
         * @return length in bytes
         */
        inline size_t len() const noexcept {
            return hdrlen;
        }

        /**
         *
         * @param hdr
         * @return length in bytes
         */
        virtual size_t update_len(const void *hdr) {}

        inline size_t update(const void *hdr) noexcept {
            hdrlen = update_len(hdr);
        }

    private:

        size_t hdrlen;

    };

    class getter {
    public:
        explicit getter(const void *b) : buf(b) {

        }

        template<typename field_type,
                typename host_type = typename field_type::host_type,
                typename func_type = field_functor<field_type>>
        inline host_type operator()(const field_type &f, func_type func = func_type()) const {
            /*
             * Strange that it compiled without "return"
             */
            return func((const char *) buf + (f.off() >> 3), f);  // NOLINT
        };

        inline void incr(const base_header &hdr) noexcept {
            (const char *) buf += hdr.len();
        }

    private:
        const void *buf;
    };

    class setter {
    public:
        explicit setter(void *b) : buf(b) {

        }

        template<typename field_type,
                typename host_type = typename field_type::host_type,
                typename func_type = field_functor<field_type>>
        inline setter &operator()(const field_type &f, const host_type &h, func_type func = func_type()) {
            func(((char *) buf) + (f.off() >> 3), f, h);
            return *this;
        };

        inline void incr(const base_header &hdr) noexcept {
            (char *) buf += hdr.len();
        }

    private:
        void *buf;
    };

    class eth_header : public base_header {
    public:
        eth_header() : base_header(ETHER_HDRLEN) {
            concatenate()(dst)(src)(type);
        }

    public:

        field_mac dst, src;
        field_word type;
    };

    class arp_header : public base_header {
    public:
        arp_header() : base_header(ARP_HDRLEN) {
            concatenate()(htype)(ptype)(hlen)(plen)
                    (oper)
                    (sha)(spa)(tha)(tpa);
        }

    public:
        field_word htype, ptype;   // Types of hardware address and protocol address
        field_byte hlen, plen;     // Lengths of hardware address and protocol address
        field_word oper;           // ARP operation
        field_mac sha, tha;       // Hardware addresses of sender and target
        field_ipv4 spa, tpa;       // Protocol addresses of sender and target

    };

    class ipv4_header : public base_header {
    public:
        /**
         * IPv4 flags
         */
        enum {
            MF = 0b001, DF = 0b010,
        };
    public:
        ipv4_header() : base_header(IPV4_HDRLEN) {
            concatenate()(version)(ihl)(diff)(tot_len)
                    (id)(flags)(frag_off)
                    (ttl)(proto)(check)
                    (src)(dst);
        }

        size_t update_len(const void *buf) override {
            getter get(buf);
            return static_cast<size_t>(get(ihl) * 4);
        }

    public:

        field_bits<4> version;      // Version
        field_bits<4> ihl;          // IHL, Internet header length in double-words(4 bytes, 32 bits)
        field_byte diff;            // Differentiated services
        field_word tot_len, id;     // Total length in bytes, and identification
        field_bits<3> flags;        // Flags
        field_bits<13> frag_off;    // Fragment offset
        field_byte ttl, proto;      // Time to live and next protocol
        field_word check;           // Header checksum
        field_ipv4 src, dst;        // Source address and destination address

    };

    class tcp_header : public base_header {
    public:
        /**
         * TCP flags
         */
        enum {
            FIN = 0x001, SYN = 0x002, RST = 0x004, PSH = 0x008,
            ACK = 0x010, URG = 0x020, ECE = 0x040, CWR = 0x080,
            NCE = 0x100
        };

    public:
        tcp_header() : base_header(TCP_HDRLEN) {
            concatenate()(src)(dst)
                    (seq)(ack_seq)
                    (doff)(flags)(window)
                    (check)(urg_ptr);
        }

        size_t update_len(const void *buf) override {
            getter get(buf);
            return static_cast<size_t>(get(doff) * 4);
        }

    public:

        field_word src, dst;                // Source port and destination port
        field_dword seq, ack_seq;           // Sequence number and acknowledgement number
        field_bits<4> doff;                 // Data offset in double-words(4 bytes, 32 bits)
        field_bits<12> flags;               // Reserved bits(3), NS(1) and flags(8)
        field_word window, check, urg_ptr;  // Windows size, header checksum and urgent pointer

    };

    class base_packet {

    public:

        virtual void update(const void *buf) {
            auto from = (const char *) buf;
            for (auto hdr_ptr : headers) {
                hdr_ptr->update(from);
                from += hdr_ptr->len();
            }
        }

    protected:
        void add_header(base_header *hdr_ptr) {
            headers.push_back(hdr_ptr);
        }

    private:
        std::list<base_header *> headers;
    };

}