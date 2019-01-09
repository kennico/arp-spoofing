//
// Created by kenny on 1/5/19.
//

#include <gtest/gtest.h>
#include "../src/fields.h"

using namespace kni;

TEST(ModifyFields, ModifyIPV4) {
    u_char buf[32] = {};

    struct unamed : public fake_pkt_base<4> {
        explicit unamed(u_char *buf) : fake_pkt_base(buf) {
            set_assign_to(ipv4);
        }

        modify_ipv4 ipv4{};
    } pkt(buf);

    pkt.ipv4 = "1.2.3.4";
    EXPECT_EQ(0x04030201, *(int *) pkt.packet());
    EXPECT_EQ(0x04030201, *(int *) (pkt.ipv4.data()));
}

TEST(ModifyFields, ModifyMAC) {
    u_char buf[32] = {};

    struct unamed : public fake_pkt_base<6> {
        explicit unamed(u_char *buf) : fake_pkt_base(buf) {
            set_assign_to(mac);
        }

        modify_mac mac{};
    } pkt(buf);

    pkt.mac = "48:48:48:48:48:48";
    EXPECT_EQ(0, memcmp(pkt.packet(), "HHHHHH", 6));
    EXPECT_EQ(0, memcmp(pkt.mac.data(), "HHHHHH", 6));
}

TEST(ModifyFields, ModifyIPV4MAC) {
    u_char buf[32] = {};

    struct unamed : public fake_pkt_base<16> {

        explicit unamed(u_char *buf) : fake_pkt_base(buf) {
            set_assign_to(src);
            set_assign_to(dst);
            set_assign_to(ipv4);
        }

        modify_mac src{};
        modify_mac dst{};
        modify_ipv4 ipv4{};

    } pkt(buf);

    pkt.src = "44:44:44:44:44:44"; // D
    pkt.dst = "56:56:56:56:56:56"; // V
    pkt.ipv4 = "9.8.7.6";

    EXPECT_EQ(0, memcmp(pkt.src.data(), "DDDDDD", 6));
    EXPECT_EQ(0, memcmp(pkt.dst.data(), "VVVVVV", 6));
    EXPECT_EQ(0x06070809, *(int *) (pkt.ipv4.data()));
}