//
// Created by kenny on 1/5/19.
//

#include <gtest/gtest.h>
#include "fields.h"

using namespace kni;

TEST(ModifyFields, ModifyIPV4) {
    struct unamed : public modifyhdr_base {
        unamed() : modifyhdr_base(sizeof(ipv4)) {

        }

        size_t update_hdr(u_char *buf) override {
            field_begin(buf)(ipv4);

            return sizeof(ipv4_t);
        }

        modify_ipv4 ipv4{};
    } pkt;

    u_char buf[32] = {};

    pkt.update(buf);
    pkt.ipv4 = "1.2.3.4";

    EXPECT_EQ(0x04030201, *(int *) (pkt.ipv4.data()));
}

TEST(ModifyFields, ModifyMAC) {
    struct unamed : public modifyhdr_base {
        unamed() : modifyhdr_base(sizeof(mac_t)) {

        }

        size_t update_hdr(u_char *buf) override {
            field_begin(buf)(mac);

            return sizeof(mac_t);
        }

        modify_mac mac{};
    } pkt;

    u_char buf[32] = {};

    pkt.update(buf);
    pkt.mac = "48:48:48:48:48:48";

    EXPECT_EQ(0, memcmp(pkt.mac.data(), "HHHHHH", 6));
}

TEST(ModifyFields, ModifyIPV4MAC) {
    struct unamed : public modifyhdr_base {
        unamed() : modifyhdr_base(sizeof(src) + sizeof(dst) + sizeof(ipv4)) {

        }

        size_t update_hdr(u_char *buf) override {
            field_begin(buf)(src)(dst)(ipv4);

            return sizeof(mac_t) * 2 + sizeof(ipv4_t);
        }

        modify_mac src{};
        modify_mac dst{};
        modify_ipv4 ipv4{};

    } pkt;

    u_char buf[32] = {};
    pkt.update(buf);

    pkt.src = "44:44:44:44:44:44"; // D
    pkt.dst = "56:56:56:56:56:56"; // V
    pkt.ipv4 = "9.8.7.6";

    EXPECT_EQ(0, memcmp(pkt.src.data(), "DDDDDD", 6));
    EXPECT_EQ(0, memcmp(pkt.dst.data(), "VVVVVV", 6));
    EXPECT_EQ(0x06070809, *(int *) (pkt.ipv4.data()));
}