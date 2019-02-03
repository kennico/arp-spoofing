#include <cstdlib>
#include <cstdint>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <memory>

namespace kni2 {

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


    template<typename unsigned_type,
            typename access_type,
            typename endianness = endian_traits<unsigned_type>>
    class unsigned_base :
            public field_bytes<unsigned_type, access_type> {

    public:
        inline explicit operator unsigned_type() const {
            auto t = this->access();
            return endianness::ntoh(*(unsigned_type *) t);
        }
    };

    template<typename int_type, typename access_type,
            typename endianness = endian_traits<int_type>>
    class unsigned_integer :
            public unsigned_base<int_type, access_type, endianness> {

    };

    /*
     * template <typename unsigned_type, typename endianness>
     *     class unsigned_integer<unsigned_type, write_access, endianness>: ...
     *
     * error: default template arguments may not be used in partial specialization
     * https://stackoverflow/a/18701381/8706476
     *
     * "The default argument applies to the specialization."
     */
    template<typename int_type, typename endianness>
    class unsigned_integer<int_type, write_access, endianness> :
            public unsigned_base<int_type, write_access, endianness> {
    private:

        using this_type = unsigned_integer<int_type, write_access, endianness>;

    public:

        inline unsigned_integer &operator=(int_type unsgn) {
            *(int_type *) (this->access()) = endianness::hton(unsgn);
            return *this;
        }
    };

    template<typename access_type>
    using unsigned_uchar = unsigned_integer<uint8_t, access_type>;

    template<typename access_type>
    using unsigned_ushort= unsigned_integer<uint16_t, access_type>;

    template<typename access_type>
    using unsigned_ulong = unsigned_integer<uint32_t, access_type>;

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


}

TEST(Usage, TmplSpecWithDefaultArg1) {
    u_char buf[4] = {0x11, 0x22, 0x33, 0x44};

    kni2::unsigned_ulong<kni2::read_access> ui;
    ui.access(
            kni2::concatenate<typename kni2::read_access::buffer_type>(buf)
    );

    EXPECT_EQ(0x11223344, (uint32_t) ui);
}

TEST(Usage, TmplSpecWithDefaultArg2) {
    u_char buf[4] = {0x11, 0x22, 0x33, 0x44};

    kni2::unsigned_ulong<kni2::write_access> ui;

    ui.access(
            kni2::concatenate<typename kni2::write_access::buffer_type>(buf)
    );

    EXPECT_EQ(0x11223344, (uint32_t) ui);

    ui = 0x55667788;
    EXPECT_EQ(0x55667788, (uint32_t) ui);
}

TEST(Usage, TmplSpecWithDefaultArg3) {
    u_char buf[4] = {0xab, 0xcd, 0xef, 0x01};

    kni2::field_bits<4, kni2::write_access> fb1;
    decltype(fb1) fb2;

    kni2::concatenate<typename kni2::write_access::buffer_type> concat(buf);

    concat(fb1)(fb2);

    EXPECT_EQ(0xa, (uint8_t) fb1);
    EXPECT_EQ(0xb, (uint8_t) fb2);

    fb1 = 7;
    fb2 = 5;

    EXPECT_EQ(0x7, (uint8_t) fb1);
    EXPECT_EQ(0x5, (uint8_t) fb2);
}