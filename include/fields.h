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

    class fld_length {
    public:
        fld_length() = default;

        explicit fld_length(size_t byte) : nbytes(byte) {

        }

        fld_length(size_t byte, size_t bit) : nbits(bit % 8), nbytes(byte + bit / 8) {

        }

        inline fld_length &operator+=(const fld_length &other) noexcept {
            nbits += other.nbits;
            nbytes += other.nbytes + nbits / 8;
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

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
#pragma ide diagnostic ignored "OCUnusedStructInspection"

    class modifyfld_base {
    public:

        inline const u_char *data() const noexcept {
            return from_ptr;
        }

        inline void bind(u_char *buf) noexcept {
            from_ptr = buf;
        }

    protected:
        u_char *from_ptr;
    };

    template<typename network_type>
    class modifybytes : public modifyfld_base {
    public:

        inline constexpr size_t bytes() const noexcept {
            return sizeof(network_type);
        }


        inline constexpr fld_length length() const noexcept {
            return fld_length(bytes());
        }

        inline void set_off(const fld_length &len) noexcept {}

    };

    template<typename network_type>
    struct endian_bytes_traits;

    template<>
    struct endian_bytes_traits<uint8_t> {
        using bytes_type = uint8_t;

        inline static bytes_type hton(bytes_type hostchar) noexcept {
            return hostchar;
        }

        inline static bytes_type ntoh(bytes_type netchar) noexcept {
            return netchar;
        }
    };

    template<>
    struct endian_bytes_traits<uint16_t> {
        using bytes_type = uint16_t;

        inline static bytes_type hton(bytes_type hostshort) noexcept {
            return htons(hostshort);
        }

        inline static bytes_type ntoh(bytes_type netshort) noexcept {
            return ntohs(netshort);
        }
    };

    template<>
    struct endian_bytes_traits<uint32_t> {
        using bytes_type = uint32_t;

        inline static bytes_type hton(bytes_type hostlong) noexcept {
            return htonl(hostlong);
        }

        inline static bytes_type ntoh(bytes_type netlong) noexcept {
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
    template<typename network_type,
            typename endian_traits=endian_bytes_traits<network_type>>
    class modify_unsigned : public modifybytes<network_type> {
    public:

        using bytes_type = typename endian_traits::bytes_type;

        inline modify_unsigned<network_type, endian_traits> &operator=(bytes_type unsgn) {
            /*
             * *(bytes_type*)(from_ptr) = endian_traits::hton(unsgn);
             * error: ‘from_ptr’ was not declared in this scope
             *
             * See https://stackoverflow.com/a/12032373/8706476
             */
            *(bytes_type *) (this->from_ptr) = endian_traits::hton(unsgn);
            return *this;
        };

        inline explicit operator bytes_type() const {
            /*
             * return endian_traits::ntoh(*(bytes_type*)(data()))
             * error: there are no arguments to ‘data’ that depend on a template parameter
             *
             * See https://stackoverflow.com/a/12032373/8706476
             */
            return endian_traits::ntoh(*(bytes_type *) (this->data()));
        }
    };

    using modify_uchar  = modify_unsigned<uint8_t>;
    using modify_ushort = modify_unsigned<uint16_t>;
    using modify_ulong  = modify_unsigned<uint32_t>;

    template<size_t nbytes>
    struct padding_bytes_traits;

    template<>
    struct padding_bytes_traits<1> {
        using padding_type = uint8_t;
    };

    template<>
    struct padding_bytes_traits<2> {
        using padding_type = uint16_t;
    };

    template<>
    struct padding_bytes_traits<3> {
        using padding_type = uint32_t;
    };

    template<>
    struct padding_bytes_traits<4> {
        using padding_type = uint32_t;
    };

    /**
     *
     * @tparam nbits (0, 32]
     * @tparam padding_traits provides padding_type
     * @tparam endian_traits
     */
    template<size_t nbits,
            typename padding_traits = padding_bytes_traits<(nbits - 1) / 8 + 1>,
            typename endian_traits  = endian_bytes_traits<typename padding_traits::padding_type>>
    class modifybits : public modifyfld_base {
    public:
        const static size_t BITS_MAXLEN = sizeof(uint32_t) * 8;

        using padding_type = typename padding_traits::padding_type;
        // 0 < nbits <= 32
        static_assert(nbits <= BITS_MAXLEN, "Length limit exceeded");
        static_assert(nbits != 0, "Zero length");
        static_assert(std::is_unsigned<padding_type>::value, "unsigned required");

    public:

        inline constexpr size_t bits() const noexcept {
            return nbits;
        }

        inline constexpr fld_length length() const noexcept {
            return fld_length(0, bits());
        }
        /**
         *
         * @param value aligned to LSB
         * @return
         */
        inline modifybits<nbits, padding_traits, endian_traits> &
        operator=(padding_type value) {
            *(padding_type *) from_ptr = (
                    ((*(padding_type *) from_ptr) & n_inv_mask) | endian_traits::hton(value << r_align));

            return *this;
        };

        inline void set_off(const fld_length &offset) {
            off = offset.bits();
            assert(off + bits() <= BITS_MAXLEN);

            auto byt = 1 + (off + bits() - 1) / 8; // How many bytes does it occupy since from_ptr?
            assert(byt > 0 && byt < 4);
            assert(sizeof(padding_type) == byt);

            r_align = byt * 8 - (off + bits()); // How many bits should I left-shift the value?

            auto mask = (padding_type) 0xFFFFFFFF;
            mask = (mask << (r_align + bits())) | ~(mask << r_align);   // NOLINT
            n_inv_mask = endian_traits::hton(mask);
        }

        /*
         * Should i avoid implicit cast?
         */
        inline explicit operator padding_type() const {
            return (*(padding_type *) data() & (~n_inv_mask)) >> r_align;                // NOLINT
        }

    private:

        size_t off{0}, r_align{0};  // How many bits are there from its end to the first 8-bit byte
        padding_type n_inv_mask{};  // Leave zeros for desired bits while ones for surrounding bits

    };

    template<size_t nbits,
            typename padding_traits = padding_bytes_traits<(nbits - 1) / 8 + 1>,
            typename endian_traits  = endian_bytes_traits<typename padding_traits::padding_type>>
    class modify_flags :
            public modifybits<nbits, padding_traits, endian_traits> {

    public:
        using parent_type  = modifybits<nbits, padding_traits, endian_traits>;
        using padding_type = typename parent_type::padding_type;
        /*
         * Name hiding - error: no match for ‘operator=’
         *
         * Using-declaration "won't be a good style" to unhide the inherited operator.
         * Re-declaring operator= also works.
         *
         * https://stackoverflow.com/a/3882455/8706476
         * https://stackoverflow.com/a/1629074/8706476
         */
        using parent_type::operator=;

    public:

        inline void set(padding_type flags) {
            parent_type::operator=((padding_type) (*this) | flags);
        }

        inline bool isset(padding_type flags) {
            return (padding_type) (*this) & endian_traits::hton(flags);
        }

    };


    // TODO should modify_ipv4 derive from modify_ulong?
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

        inline explicit operator ipv4_t() const noexcept {
            return *(ipv4_t *) data();
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

#pragma clang diagnostic pop

    class modifyhdr_base {

    private:
        class hdr_builder {
        public:

            explicit hdr_builder(u_char *buf_) : buf(buf_) {

            }

            template<typename Field>
            inline hdr_builder &operator()(Field &field) noexcept {
                field.set_off(acc_len());
                field.bind(buf + len.bytes());
                len += field.length();

                return *this;
            }

            inline const fld_length &acc_len() const noexcept {
                return len;
            }

        private:
            u_char *buf{nullptr};
            fld_length len{};
        };

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

    /**
     * IPv4 flags
     */
    enum {
        MF = 0b001, DF = 0b010,
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

    public:

        inline bool validate() const {
            return cal_check() == 0;
        }

        inline uint16_t cal_check() const {
            return compute_check(version.data(), static_cast<size_t>((uint8_t) ihl * 4));
        }

        /**
         * Firstly it sets check to zero and therefore clears the old checksum
         */
        inline void set_check() {
            check = 0;
            check = cal_check();
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

    /**
     * TCP flags
     */
    enum {
        FIN = 0x001, SYN = 0x002, RST = 0x004, PSH = 0x008,
        ACK = 0x010, URG = 0x020, ECE = 0x040, CWR = 0x080,
        NCE = 0x100
    };

    struct pseudo_ipv4 : public modifyhdr_base {
        pseudo_ipv4() : modifyhdr_base(12) {

        }

        modify_ipv4 src{}, dst{};
        modify_uchar rsv{}, proto{};
        /*
         * This field is not presented in a TCP header. Instead, it is derived from an IP header
         *
         * tcp_len = ip.tot_len - ip.ihl * 4 measured in bytes.
         */
        modify_ushort tcp_len{};

        size_t update_hdr(u_char *buf) override {
            field_begin(buf)(src)(dst)(rsv)(proto)(tcp_len);
            rsv = 0;
            proto = IPPROTO_TCP;

            return 12;
        }

    };

    // IPv4 options are not supported to be modified in this way
    struct modifyhdr_tcp : public modifyhdr_base {
        modify_ushort src{}, dst{};                     // Source port and destination port
        modify_ulong seq{}, ack_seq{};                  // Sequence number and acknowledgement number
        modifybits<4> doff{};                           // Data offset in double-words(4 bytes, 32 bits)
        modify_flags<12> flags{};                       // Reserved bits(3), NS(1) and flags(8)
        modify_ushort window{}, check{}, urg_ptr{};     // Windows size, header checksum and urgent pointer

        modifyhdr_tcp() : modifyhdr_base(TCP_HDRLEN) {

        }

    public:

        /**
         *
         * @param pseudo
         * @return
         */
        inline bool validate(const void *pseudo, size_t bytes) const {
            return cal_check(pseudo, bytes) == 0;
        }

        inline uint16_t cal_check(const void *pseudo, size_t bytes) const {
            return ~sum_all_words(
                    src.data(),
                    static_cast<size_t>((uint8_t) doff * 4), sum_all_words(pseudo, bytes));
        }

        inline void set_check(const void *pseudo, size_t bytes) {
            check = 0;
            check = cal_check(pseudo, bytes);
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

        /**
         * Update the binding pointer of each header
         *
         * @param buf
         */
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

}
