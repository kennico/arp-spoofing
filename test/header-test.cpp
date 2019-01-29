//
// Created by kenny on 1/27/19.
//

#include <gtest/gtest.h>
#include <arpspf.h>
#include <linux/tcp.h>
#include "fields.h"

TEST(ModifyHeader, UpdateEthernet) {
    /* Frame (14 bytes) */
    const u_char pkt[] = {
            0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f, 0x20, 0x76,
            0x93, 0x3d, 0x8b, 0x57, 0x08, 0x06,
    };

    u_char buf[sizeof(pkt)];

    kni::modifyhdr_ether ethHdr;
    ethHdr.update(buf);

    ethHdr.dst = "50:2b:73:dc:54:3f";
    ethHdr.src = "20:76:93:3d:8b:57";
    ethHdr.type = ETH_P_ARP;

    for (int i = 0; i < sizeof(pkt); ++i)
        EXPECT_EQ(pkt[i], buf[i]) << "at byte " << i;
}

TEST(ModifyHeader, UpdateArp) {
    /* Frame (28 bytes) */
    const u_char pkt[] = {
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
            0x20, 0x76, 0x93, 0x3d, 0x8b, 0x57, 0xc0, 0xa8,
            0xe1, 0x01, 0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f,
            0xc0, 0xa8, 0xe1, 0xb1
    };

    u_char buf[sizeof(pkt)];

    kni::modifyhdr_arp arpHdr;
    arpHdr.update(buf);

    arpHdr.htype = ARPHRD_ETHER;
    arpHdr.ptype = ETH_P_IP;
    arpHdr.hlen = 6;
    arpHdr.plen = 4;

    arpHdr.sha = "20:76:93:3d:8b:57";
    arpHdr.spa = "192.168.225.1";
    arpHdr.tha = "50:2b:73:dc:54:3f";
    arpHdr.tpa = "192.168.225.177";
    arpHdr.oper = ARPOP_REPLY;

    for (int i = 0; i < sizeof(pkt); ++i)
        EXPECT_EQ(pkt[i], buf[i]) << "at byte " << i;
}

TEST(ModifyHeader, UpdateIpv4) {

    /* Frame (123 bytes) */
    static const u_char pkt[] = {
            0x45, 0xd0, 0x00, 0x6d, 0x43, 0x8c, 0x00, 0x00,
            0x40, 0x01, 0xf2, 0x2f, 0xc0, 0xa8, 0xe1, 0xb1,
            0xc0, 0xa8, 0xe1, 0x01
    };

    u_char buf[sizeof(pkt)] = {0};

    kni::modifyhdr_ipv4 ipHdr;
    ipHdr.update(buf);

    ipHdr.version = 4;
    ipHdr.ihl = 5;
    ipHdr.diff = 0xd0;
    ipHdr.tot_len = 109;
    ipHdr.id = 0x438c;
    ipHdr.flags = 0x00;
    ipHdr.frag_off = 0x00;
    ipHdr.ttl = 64;
    ipHdr.proto = IPPROTO_ICMP;
    ipHdr.check = 0xf22f;
    ipHdr.src = "192.168.225.177";
    ipHdr.dst = "192.168.225.1";


    for (int i = 0; i < sizeof(pkt); ++i)
        EXPECT_EQ(pkt[i], buf[i]) << "at byte " << i;
}

TEST(ModifyHeader, UpdateTcpFlagsSYN) {
    const u_char pkt[] = {
            0x9c, 0xfe, 0x01, 0xbb, 0x53, 0xe4, 0x5a, 0xee,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10,
            0x94, 0xc3, 0x00, 0x00,
    };

    u_char buf[sizeof(pkt)];

    kni::modifyhdr_tcp tcpHdr;
    tcpHdr.update(buf);

    tcpHdr.src = 40190;
    tcpHdr.dst = 443;
    tcpHdr.seq = 0x53e45aee;
    tcpHdr.ack_seq = 0x00000000;
    tcpHdr.doff = 10;
    tcpHdr.flags.set(kni::tcp_flags::SYN);

    tcpHdr.window = 29200;
    tcpHdr.check = 0x94c3;
    tcpHdr.urg_ptr = 0;

    for (int i = 0; i < sizeof(pkt); ++i)
        EXPECT_EQ(pkt[i], buf[i]) << "at byte " << i;
}

TEST(ModifyHeader, UpdateTcpFlagsRST) {
    /* Frame (54 bytes) */
    const unsigned char pkt[20] = {
            0x00, 0x50, 0xea, 0xaa, 0x0d, 0xda, 0x55, 0xe2,
            0x7b, 0x8d, 0xf5, 0x31, 0x50, 0x04, 0x04, 0x00,
            0xa5, 0x6f, 0x00, 0x00
    };

    u_char buf[sizeof(pkt)];

    kni::modifyhdr_tcp tcpHdr;
    tcpHdr.update(buf);

    tcpHdr.src = 80;
    tcpHdr.dst = 60074;
    tcpHdr.seq = 0x0dda55e2;
    tcpHdr.ack_seq = 0x7b8df531;
    tcpHdr.doff = 5;
    tcpHdr.flags.set(kni::tcp_flags::RST);

    tcpHdr.window = 1024;
    tcpHdr.check = 0xa56f;
    tcpHdr.urg_ptr = 0;

    for (int i = 0; i < sizeof(pkt); ++i)
        EXPECT_EQ(pkt[i], buf[i]) << "at byte " << i;
}
