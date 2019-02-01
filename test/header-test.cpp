//
// Created by kenny on 1/27/19.
//

#include <gtest/gtest.h>
#include <arpspf.h>
#include <linux/tcp.h>
#include "fields.h"

TEST(ModifyHeader, EthernetWrite) {
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

TEST(ModifyHeader, ArpWrite) {
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

TEST(ModifyHeader, Ipv4Read) {
    u_char pkt[] = {
            0x45, 0x00,
            0x00, 0x3c, 0x14, 0xdb, 0x40, 0x00, 0x40, 0x06, /* .<..@.@. */
            0x8f, 0x5f, 0xc0, 0xa8, 0xe1, 0xb1, 0xcb, 0xd0, /* ._...... */
            0x28, 0x57,                                      /* .. */
    };

    kni::modifyhdr_ipv4 ipHdr;
    ipHdr.update(pkt);

    EXPECT_EQ(4, (uint8_t) ipHdr.version);
    EXPECT_EQ(5, (uint8_t) ipHdr.ihl);
    EXPECT_EQ(0, (uint8_t) ipHdr.diff);
    EXPECT_EQ(60, (uint16_t) ipHdr.tot_len);
    EXPECT_EQ(0x14db, (uint16_t) ipHdr.id);
    EXPECT_TRUE(ipHdr.flags.isset(kni::DF));
    EXPECT_EQ(64, (uint8_t) ipHdr.ttl);
    EXPECT_EQ(0, (uint16_t) ipHdr.frag_off);
    EXPECT_EQ(IPPROTO_TCP, (uint8_t) ipHdr.proto);
    EXPECT_EQ(0x8f5f, (uint16_t) ipHdr.check);

    EXPECT_EQ("192.168.225.177", kni::to_string((kni::ipv4_t) ipHdr.src));
    EXPECT_EQ("203.208.40.87", kni::to_string((kni::ipv4_t) ipHdr.dst));
}

TEST(ModifyHeader, Ipv4Write) {
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

TEST(ModifyHeader, Ipv4CalChecksum1) {
    /*
     * https://www.thegeekstuff.com/2012/05/ip-header-checksum
     */
    u_char pkt[] = {
            0x45, 0x00,
            0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, /* .<..@.@. */
            0xb1, 0xe6, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, /* ._...... */
            0x0a, 0x0c,                                      /* .. */
    };

    kni::modifyhdr_ipv4 ipHdr;
    ipHdr.update(pkt);
    ipHdr.check = 0;
    EXPECT_EQ(0xb1e6, ipHdr.cal_check());
}

TEST(ModifyHeader, Ipv4CalChecksum2) {
    /*
     * https://en.m.wikipedia.org/wiki/IPv4_header_checksum
     */
    u_char pkt[] = {
            0x45, 0x00,
            0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, /* .<..@.@. */
            0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, /* ._...... */
            0x00, 0xc7,                                      /* .. */
    };

    kni::modifyhdr_ipv4 ipHdr;
    ipHdr.update(pkt);
    ipHdr.check = 0;
    EXPECT_EQ(0xb861, ipHdr.cal_check());
}

TEST(ModifyHeader, Ipv4CalChecksum3) {
    u_char pkt[] = {
            0x45, 0x00,
            0x00, 0x3c, 0x14, 0xdb, 0x40, 0x00, 0x40, 0x06, /* .<..@.@. */
            0x8f, 0x5f, 0xc0, 0xa8, 0xe1, 0xb1, 0xcb, 0xd0, /* ._...... */
            0x28, 0x57,                                      /* .. */
    };

    kni::modifyhdr_ipv4 ipHdr;
    ipHdr.update(pkt);

    ipHdr.check = 0;
    EXPECT_EQ(0x8f5f, ipHdr.cal_check());
}

TEST(ModifyHeader, Ipv4ValidateChecksum1) {
    u_char pkt[] = {
            0x45, 0x00,
            0x00, 0x3c, 0x14, 0xdb, 0x40, 0x00, 0x40, 0x06, /* .<..@.@. */
            0x8f, 0x5f, 0xc0, 0xa8, 0xe1, 0xb1, 0xcb, 0xd0, /* ._...... */
            0x28, 0x57,                                      /* .. */
    };

    kni::modifyhdr_ipv4 ipHdr;
    ipHdr.update(pkt);

    EXPECT_TRUE(ipHdr.validate());
}

TEST(ModifyHeader, Ipv4ValidateChecksum2) {
    u_char pkt[] = {
            0x45, 0x00,
            0x00, 0x3c, 0x14, 0xdb, 0x40, 0x00, 0x40, 0x06, /* .<..@.@. */
            0x8f, 0x5f, 0xc0, 0xa8, 0xe1, 0xb1, 0xcb, 0xd0, /* ._...... */
            0x28, 0x57,                                      /* .. */
    };

    kni::modifyhdr_ipv4 ipHdr;
    ipHdr.update(pkt);
    ipHdr.set_check();
    EXPECT_TRUE(ipHdr.validate());
}

TEST(ModifyHeader, TcpValidateChecksum) {

    u_char pkt[] = {
            0x9c, 0xfe, 0x01, 0xbb, 0x53, 0xe4, 0x5a, 0xee,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10,
            0x94, 0xc3, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
            0x04, 0x02, 0x08, 0x0a, 0x00, 0x36, 0x5c, 0xe8,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07
    };

    kni::modifyhdr_tcp tcpHdr;
    tcpHdr.update(pkt);

    u_char buf[12];

    kni::pseudo_ipv4 pseudo_ip;
    pseudo_ip.update(buf);

    pseudo_ip.src = "192.168.225.177";
    pseudo_ip.dst = "203.208.40.87";
    pseudo_ip.rsv = 0;
    pseudo_ip.tcp_len = 40;


    EXPECT_TRUE(tcpHdr.validate(buf, sizeof(buf)));
}

TEST(ModifyHeader, TcpValidateChecksum2) {
    u_char pkt[] = {
            0x9c, 0xfe, 0x01, 0xbb, 0x53, 0xe4, 0x5a, 0xee,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10,
            0x94, 0xc3, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
            0x04, 0x02, 0x08, 0x0a, 0x00, 0x36, 0x5c, 0xe8,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07
    };

    kni::modifyhdr_tcp tcpHdr;
    tcpHdr.update(pkt);

    u_char buf[12];

    kni::pseudo_ipv4 pseudo_ip;
    pseudo_ip.update(buf);

    pseudo_ip.src = "192.168.225.177";
    pseudo_ip.dst = "203.208.40.87";
    pseudo_ip.rsv = 0;
    pseudo_ip.tcp_len = 40;

    tcpHdr.check = 0;
    tcpHdr.set_check(buf, sizeof(buf));
    EXPECT_TRUE(tcpHdr.validate(buf, sizeof(buf)));
}

TEST(ModifyHeader, TcpRead) {
    u_char pkt[] = {
            0x9c, 0xfe, 0x01, 0xbb, 0x53, 0xe4, 0x5a, 0xee,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10,
            0x94, 0xc3, 0x00, 0x00,
    };

    kni::modifyhdr_tcp tcpHdr;
    tcpHdr.update(pkt);

    EXPECT_EQ(40190, (uint16_t) tcpHdr.src);
    EXPECT_EQ(443, (uint16_t) tcpHdr.dst);
    EXPECT_EQ(0x53e45aee, (uint32_t) tcpHdr.seq);
    EXPECT_EQ(0, (uint32_t) tcpHdr.ack_seq);
    EXPECT_EQ(10, (uint8_t) tcpHdr.doff);
    EXPECT_TRUE(tcpHdr.flags.isset(kni::SYN));
    EXPECT_EQ(29200, (uint16_t) tcpHdr.window);
    EXPECT_EQ(0, (uint16_t) tcpHdr.urg_ptr);
}

TEST(ModifyHeader, TcpWriteSYN) {
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
    tcpHdr.flags.set(kni::SYN);

    tcpHdr.window = 29200;
    tcpHdr.check = 0x94c3;
    tcpHdr.urg_ptr = 0;

    for (int i = 0; i < sizeof(pkt); ++i)
        EXPECT_EQ(pkt[i], buf[i]) << "at byte " << i;
}

TEST(ModifyHeader, TcpWriteRST) {
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
    tcpHdr.flags.set(kni::RST);

    tcpHdr.window = 1024;
    tcpHdr.check = 0xa56f;
    tcpHdr.urg_ptr = 0;

    for (int i = 0; i < sizeof(pkt); ++i)
        EXPECT_EQ(pkt[i], buf[i]) << "at byte " << i;
}
