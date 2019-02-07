//
// Created by kenny on 2/5/19.
//
#ifdef KNI_DEBUG

#include <gtest/gtest.h>
#include "nethdrs.h"

TEST(NetHeaders, SetGetFieldByte) {
    u_char buf[4] = {0x12, 0x34, 0x56, 0x78};

    kni::field_byte byte;

    kni::setter set(buf);
    set(byte, 0x99);

    kni::getter get(buf);
    EXPECT_EQ(0x99, get(byte));
}

TEST(NetHeaders, SetGetFieldWord) {
    u_char buf[4] = {0x12, 0x34, 0x56, 0x78};

    kni::field_word word;

    kni::setter set(buf);
    set(word, 0xabcd);

    kni::getter get(buf);
    EXPECT_EQ(0xabcd, get(word));
}

TEST(NetHeaders, SetGetFieldDoubleWord) {
    u_char buf[4] = {0x12, 0x34, 0x56, 0x78};

    kni::field_dword dword;

    kni::setter set(buf);
    set(dword, 0xaabbccdd);

    kni::getter get(buf);
    EXPECT_EQ(0xaabbccdd, get(dword));
}

TEST(NetHeaders, SetGetFieldIPv4) {
    kni::ipv4_t buf;

    kni::field_ipv4 ipv4;

    kni::setter set(&buf);
    set(ipv4, "192.168.225.1");

    kni::getter get(&buf);
    EXPECT_EQ("192.168.225.1", kni::to_string(get(ipv4)));
}

TEST(NetHeaders, SetGetFieldMAC) {
    kni::mac_t buf;

    kni::field_mac mac;
    EXPECT_EQ(6, mac.bytes());

    kni::setter set(&buf);
    set(mac, "11:22:33:44:55:66");

    kni::getter get(&buf);
    EXPECT_EQ("11:22:33:44:55:66", kni::to_string(get(mac)));
}

TEST(NetHeaders, SetGetFieldBits1) {
    u_char buf[4] = {0x12, 0x34, 0x56, 0x78};

    kni::field_bits<4> bits;
    bits.off(4);

    kni::setter set(buf);
    set(bits, 0x05);

    kni::getter get(buf);
    EXPECT_EQ(0x05, get(bits));
}

TEST(NetHeaders, SetGetFieldBits2) {
    u_char buf[4] = {0x12, 0x34, 0x56, 0x78};

    kni::field_bits<4> bits;
    bits.off(12);

    kni::setter set(buf);
    set(bits, 0x05);

    kni::getter get(buf);
    EXPECT_EQ(0x05, get(bits));
}

TEST(NetHeaders, SetGetFieldBits3) {
    u_char buf[4] = {0x12, 0x34, 0x56, 0x78};

    kni::field_bits<3> bits;
    bits.off(12);

    kni::setter set(buf);
    set(bits, 0x05);

    kni::getter get(buf);
    EXPECT_EQ(0x05, get(bits));
}

#endif // KNI_DEBUG
