//
// Created by kenny on 1/29/19.
//
#include <gtest/gtest.h>

template<size_t nbytes>
struct bits_traits;

template<>
struct bits_traits<1> {
    using enlarged_t = uint8_t;
};

template<>
struct bits_traits<2> {
    using enlarged_t = uint16_t;
};

template<>
struct bits_traits<3> {
    using enlarged_t = uint32_t;
};

template<>
struct bits_traits<4> {
    using enlarged_t = uint32_t;
};


template<size_t nbits,
        typename traits = bits_traits<(nbits - 1) / 8 + 1>>
struct modify_bits {
    using enlarged_t = typename traits::enlarged_t;

public:
    inline std::string f() const noexcept {
        return typeid(enlarged_t).name(); // https://stackoverflow.com/a/20170989
    }
};

TEST(Usage, IntegerTmplTraits) {
    modify_bits<1> m1;
    EXPECT_EQ(typeid(uint8_t).name(), m1.f());

    modify_bits<4> m4;
    EXPECT_EQ(typeid(uint8_t).name(), m4.f());

    modify_bits<6> m6;
    EXPECT_EQ(typeid(uint8_t).name(), m6.f());

    modify_bits<8> m8;
    EXPECT_EQ(typeid(uint8_t).name(), m8.f());

    modify_bits<12> m12;
    EXPECT_EQ(typeid(uint16_t).name(), m12.f());

    modify_bits<20> m20;
    EXPECT_EQ(typeid(uint32_t).name(), m20.f());
}

