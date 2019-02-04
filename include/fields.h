//
// Created by kenny on 1/6/19.
//

#pragma once

#include <cassert>
#include <list>
#include <arpa/inet.h>

#include "pkt.h"
#include "utils.h"

namespace kni {

    class field_length {
    public:
        field_length() = default;

        explicit field_length(size_t byte) : nbytes(byte) {

        }

        field_length(size_t byte, size_t bit) : nbits(bit % 8), nbytes(byte + bit / 8) {

        }

        inline field_length &operator+=(const field_length &other) noexcept {
            nbits += other.bits();
            nbytes += other.bytes() + nbits / 8;
            nbits %= 8;

            return *this;
        }

        inline size_t bytes() const noexcept {
            return nbytes;
        }

        inline size_t bits() const noexcept {
            return nbits;
        }

    private:

        size_t nbytes{0}, nbits{0};
    };

    template<typename T>
    class access_bytes {
    public:

        using buffer_type = T;

        inline buffer_type operator()() const noexcept {
            return buf_ptr;
        }

        template<typename concat_type>
        inline void operator()(const concat_type &concat) noexcept {
            auto t = concat.curr();
            buf_ptr = t;
        }

    private:
        buffer_type buf_ptr;
    };

    /*
     * TODO Deduce buffer type in a more elegant way
     */
    using read_access = access_bytes<const u_char *>;
    using write_access= access_bytes<u_char *>;

    template<typename network_type>
    class field_bytes_base {
    public:
        inline constexpr size_t bytes() const noexcept {
            return sizeof(network_type);
        }

        inline constexpr field_length length() const noexcept {
            return field_length(bytes());
        }
    };

    template<typename network_type,
            typename access_type>
    class field_bytes :
            public field_bytes_base<network_type> {

    public:
        access_type access;
    };

    template<typename access_type>
    class field_ipv4_base : public field_bytes<ipv4_t, access_type> {
    public:
        inline explicit operator ipv4_t() const noexcept {
            auto ui = ntohl(*(uint32_t *) (this->access()));
            return *(ipv4_t *) ui;
        }
    };

    template<typename access_type>
    class field_ipv4 : public field_ipv4_base<access_type> {

    };

    template<>
    class field_ipv4<write_access> : public field_ipv4_base<write_access> {
    public:

        inline field_ipv4<write_access> &operator=(ipv4_t addr) {
            *(ipv4_t *) (this->access()) = addr;
            return *this;
        }

        inline field_ipv4<write_access> &operator=(const std::string &ip) {
            operator=(ip.c_str());
            return *this;
        }

        inline field_ipv4<write_access> &operator=(const char *ip) {
            assert(inet_pton(AF_INET, ip, this->access()));
            return *this;
        }

    };

    template<typename access_type>
    class field_mac : public field_bytes<mac_t, access_type> {
    public:
    };

    template<>
    class field_mac<write_access> : public field_bytes<mac_t, write_access> {
    public:
        inline field_mac<write_access> &operator=(const char *mac) {
            assert(mac_pton(mac, this->access()));
            return *this;
        }

        inline field_mac<write_access> &operator=(const std::string &mac) {
            assert(mac_pton(mac.c_str(), this->access()));
            return *this;
        }

        inline field_mac<write_access> &operator=(const u_char *mac) {
            for (int i = 0; i < 6; ++i)
                this->access()[i] = mac[i];
            return *this;
        }

        inline field_mac<write_access> &operator=(const mac_t &mac) {
            operator=(mac.data);
            return *this;
        }
    };

    template<typename network_type>
    struct endian_traits;

    template<>
    struct endian_traits<uint8_t> {
        using int_type = uint8_t;

        inline static int_type hton(int_type hostchar) noexcept {
            return hostchar;
        }

        inline static int_type ntoh(int_type netchar) noexcept {
            return netchar;
        }
    };

    template<>
    struct endian_traits<uint16_t> {
        using int_type = uint16_t;

        inline static int_type hton(int_type hostshort) noexcept {
            return htons(hostshort);
        }

        inline static int_type ntoh(int_type netshort) noexcept {
            return ntohs(netshort);
        }
    };

    template<>
    struct endian_traits<uint32_t> {
        using int_type = uint32_t;

        inline static int_type hton(int_type hostlong) noexcept {
            return htonl(hostlong);
        }

        inline static int_type ntoh(int_type netlong) noexcept {
            return ntohl(netlong);
        }
    };

    /**
     * IPv4, IPv6 and MAC address type don't inherit this class and therefore
     * explicit casting are not supported for these types currently.
     *
     *
     * @tparam network_type
     * @tparam endian_traits
     */
    template<typename unsigned_type,
            typename access_type,
            typename endianness = endian_traits<unsigned_type>>
    class field_unsigned_base :
            public field_bytes<unsigned_type, access_type> {

    public:
        inline explicit operator unsigned_type() const {

            return endianness::ntoh(*(unsigned_type *) this->access());
        }
    };

    template<typename int_type, typename access_type,
            typename endianness = endian_traits<int_type>>
    class field_unsigned :
            public field_unsigned_base<int_type, access_type, endianness> {

    };

    /*
    * template <typename unsigned_type, typename endianness>
    *     class field_unsigned<unsigned_type, write_access, endianness>: ...
    *
    * error: default template arguments may not be used in partial specialization
    * https://stackoverflow/a/18701381/8706476
    *
    * "The default argument applies to the specialization."
    */
    template<typename int_type, typename endianness>
    class field_unsigned<int_type, write_access, endianness> :
            public field_unsigned_base<int_type, write_access, endianness> {

    public:

        inline field_unsigned &operator=(int_type unsgn) {
            *(int_type *) (this->access()) = endianness::hton(unsgn);
            return *this;
        }
    };

    /*
     * TODO Provide an implementation of assignment operator between instances of modifybits
     */
    template<typename access_type>
    using field_uchar = field_unsigned<uint8_t, access_type>;

    template<typename access_type>
    using field_ushort= field_unsigned<uint16_t, access_type>;

    template<typename access_type>
    using field_ulong = field_unsigned<uint32_t, access_type>;


    template<size_t nbits>
    struct cal_padding {
        constexpr const static size_t bytes = (nbits - 1) / 8 + 1;
    };

    template<size_t nbytes>
    struct align_bits;

    template<>
    struct align_bits<1> {
        using aligned_type = uint8_t;
    };

    template<>
    struct align_bits<2> {
        using aligned_type = uint16_t;
    };

    template<>
    struct align_bits<3> {
        using aligned_type = uint32_t;
    };

    template<>
    struct align_bits<4> {
        using aligned_type = uint32_t;
    };

    template<size_t nbits>
    struct bits_padding_traits {
        constexpr const static size_t bytes = cal_padding<nbits>::bytes;
        using aligned_type  = typename align_bits<bytes>::aligned_type;
        using endianness    = endian_traits<aligned_type>;
    };

    template<size_t nbits, typename access_type,
            typename traits = bits_padding_traits<nbits>>
    class field_bits_base {
    public:
        constexpr const static size_t MAX_BITS = sizeof(uint32_t) * 8;

        using aligned_type = typename traits::aligned_type;
        using endianness   = typename traits::endianness;
        using buffer_type  = typename access_type::buffer_type;

        // 0 < nbits <= 32
        static_assert(nbits <= MAX_BITS, "length limit exceeded");
        static_assert(nbits != 0, "zero length");
        static_assert(std::is_unsigned<aligned_type>::value, "unsigned required");

    public:

        inline constexpr size_t bits() const noexcept {
            return nbits;
        }

        inline constexpr field_length length() const noexcept {
            return field_length(0, bits());
        }

        /**
         * Mimic the overloaded operator of access_type
         *
         * @return
         */
        inline buffer_type access() const {
            return this->accessor();
        }

        /**
         * Mimic the overloaded operator of access_type
         *
         * @tparam concat_type
         * @param concat
         */
        template<typename concat_type>
        inline void access(const concat_type &concat) {
            this->accessor(concat);
            this->off = concat.acc_len().bits();

            assert(off + bits() <= MAX_BITS);

            auto byt = 1 + (off + bits() - 1) / 8; // How many bytes does it occupy since from_ptr?
            assert(byt > 0 && byt < 4);
            assert(sizeof(aligned_type) == byt);

            r_align = byt * 8 - (off + bits()); // How many bits should I left-shift the value?

            auto mask = (aligned_type) 0xFFFFFFFF;
            mask = (mask << (r_align + bits())) | ~(mask << r_align);   // NOLINT
            n_inv_mask = endianness::hton(mask);
        }

        /*
         * TODO Avoid implicit cast?
         */
        inline explicit operator aligned_type() const {
            return (*(aligned_type *) this->access() & (~n_inv_mask)) >> r_align;                // NOLINT
        }

    private:
        access_type accessor{};

    protected:

        size_t off{0}, r_align{0};  // How many bits are there from its end to the first 8-bit byte
        aligned_type n_inv_mask{};  // Leave zeros for desired bits while ones for surrounding bits

    };

    template<size_t nbits, typename access_type,
            typename traits = bits_padding_traits<nbits>>
    class field_bits :
            public field_bits_base<nbits, access_type, traits> {
    public:
    };

    template<size_t nbits, typename traits>
    class field_bits<nbits, write_access, traits> :
            public field_bits_base<nbits, write_access, traits> {
    private:

        using this_type = field_bits<nbits, write_access, traits>;
        using base_type = field_bits_base<nbits, write_access, traits>;

    public:
        using endianness    = typename base_type::endianness;
        using aligned_type  = typename base_type::aligned_type;

        inline this_type &operator=(aligned_type value) {
            *(aligned_type *) (this->access()) =
                    (*(aligned_type *) (this->access())) & this->n_inv_mask |
                    endianness::hton(value << this->r_align); // NOLINT
            return *this;
        }
    };

    template<size_t nbits, typename access_type,
            typename traits = bits_padding_traits<nbits>>
    class field_flags_base :
            public field_bits<nbits, access_type, traits> {

    public:
        using parent_type  = field_bits<nbits, access_type, traits>;
        using aligned_type = typename parent_type::aligned_type;
        using endianness = typename parent_type::endianness;
        using parent_type::operator=;

    public:

        inline bool isset(aligned_type flags) {
            return (aligned_type) (*this) & endianness::hton(flags);
        }

    };

    template<size_t nbits, typename access_type,
            typename traits = bits_padding_traits<nbits>>
    class field_flags :
            public field_flags_base<nbits, access_type, traits> {

    };

    template<size_t nbits, typename traits>
    class field_flags<nbits, write_access, traits> :
            public field_flags_base<nbits, write_access, traits> {

    public:
        using parent_type = field_flags_base<nbits, write_access, traits>;
        using aligned_type = typename parent_type::aligned_type;

        inline void set(aligned_type flags) {

            parent_type::operator=((aligned_type) (*this) | flags);
        }
    };

    class base_header {

    private:
        template<typename buffer_type>
        class concatenate {
        public:
            explicit concatenate(buffer_type buf) : buf_ptr(buf) {

            }

            template<typename field_type>
            inline concatenate<buffer_type> &operator()(field_type &field) {
                field.access((const concatenate<buffer_type> &) *this);
                off += field.length();

                return *this;
            }

            inline buffer_type curr() const noexcept {
                return buf_ptr + off.bytes();
            }

            inline const field_length &acc_len() const noexcept {
                return off;
            }

        private:
            buffer_type buf_ptr{};
            field_length off{};
        };

    public:

        explicit base_header(size_t init_len) : len(init_len) {

        }

        inline size_t hdrlen() const noexcept {
            return len;
        }

    protected:

        template<typename buffer_type>
        inline static concatenate<buffer_type> field_begins(buffer_type buf) noexcept {
            return concatenate<buffer_type>(buf);
        }

    protected:
        size_t len{0};
    };

    template<typename access_type>
    class ethernet_header : public base_header {
    public:
        using buffer_type = typename access_type::buffer_type;

        ethernet_header() : base_header(ETHER_HDRLEN) {

        }

        inline void update(buffer_type buf) {
            field_begins(buf)(src)(dst)(type);
        }

    public:
        field_mac<access_type> src{}, dst{};
        field_ushort<access_type> type{};
    };

    template<typename access_type>
    class arp_header : public base_header {
    public:

        using buffer_type = typename access_type::buffer_type;

        arp_header() : base_header(ARP_HDRLEN) {

        }

        inline void update(buffer_type buf) {
            field_begins(buf)
                    (htype)(ptype)(hlen)(plen)
                    (oper)
                    (sha)(spa)(tha)(tpa);
        }

    public:

        field_mac<access_type> sha{}, tha{};
        field_ushort<access_type> htype{}, ptype{}, oper{};
        field_ipv4<access_type> spa{}, tpa{};
        field_uchar<access_type> hlen{}, plen{};
    };
    /**
     * IPv4 flags
     */
    enum {
        MF = 0b001, DF = 0b010,
    };

    template<typename access_type>
    class ipv4_header : public base_header {
    public:

        using buffer_type = typename access_type::buffer_type;

        ipv4_header() : base_header(IPV4_HDRLEN) {

        }

        inline void update(buffer_type buf) {
            field_begins(buf)(version)(ihl)(diff)(tot_len)
                    (id)(flags)(frag_off)
                    (ttl)(proto)(check)
                    (src)(dst);

            len = static_cast<size_t>((uint8_t) ihl * 4);
        }

        inline bool validate() const {
            return cal_check() == 0;
        }

        inline uint16_t cal_check() const {
            return compute_check(version.access(), static_cast<size_t>((uint8_t) ihl * 4));
        }

    public:

        field_bits<4, access_type> version{}, ihl{};
        field_flags<3, access_type> flags{};
        field_uchar<access_type> diff{}, ttl{}, proto{};
        field_ushort<access_type> tot_len{}, id{}, check{};
        field_bits<13, access_type> frag_off{};
        field_ipv4<access_type> src{}, dst{};

    };

    class pseudo_ipv4 : public base_header {
    public:
        pseudo_ipv4() :
                base_header(sizeof(ipv4_t) * 2 + sizeof(uint8_t) * 2 + sizeof(uint16_t)),
                mem(new u_char[hdrlen()]) {

            field_begins(mem.get())(src)(dst)(rsv)(proto)(tcp_len);
        }

    public:

        inline const u_char *data() const noexcept {
            return mem.get();
        }

    public:

        field_ipv4<write_access> src{}, dst{};
        field_uchar<write_access> rsv{}, proto{};
        field_ushort<write_access> tcp_len{};
    private:
        std::unique_ptr<u_char[]> mem;
    };

    /**
     * TCP flags
     */
    enum {
        FIN = 0x001, SYN = 0x002, RST = 0x004, PSH = 0x008,
        ACK = 0x010, URG = 0x020, ECE = 0x040, CWR = 0x080,
        NCE = 0x100
    };

    template<typename access_type>
    class tcp_header : public base_header {
    public:
        tcp_header() : base_header(TCP_HDRLEN) {

        }

        using buffer_type = typename access_type::buffer_type;

        inline void update(buffer_type buf) {
            field_begins(buf)(src)(dst)
                    (seq)(ack_seq)
                    (doff)(flags)(window)
                    (check)(urg_ptr);

            len = static_cast<size_t>((uint8_t) doff * 4);
        }

        inline bool validate(const void *pseudo, size_t bytes) const {
            return cal_check(pseudo, bytes) == 0;
        }

        inline uint16_t cal_check(const void *pseudo, size_t bytes) const {
            return ~sum_all_words(
                    src.access(),
                    static_cast<size_t>((uint8_t) doff * 4), sum_all_words(pseudo, bytes));
        }

    public:
        field_ushort<access_type> src{}, dst{}, window{}, check{}, urg_ptr{};
        field_ulong<access_type> seq{}, ack_seq{};
        field_bits<4, access_type> doff{};
        field_flags<12, access_type> flags{};
    };

    using read_eth = ethernet_header<read_access>;
    using read_arp = arp_header<read_access>;
    using read_ipv4 = ipv4_header<read_access>;
    using read_tcp = tcp_header<read_access>;

    using write_eth = ethernet_header<write_access>;
    using write_arp = arp_header<write_access>;
    using write_ipv4 = ipv4_header<write_access>;
    using write_tcp = tcp_header<write_access>;
}
