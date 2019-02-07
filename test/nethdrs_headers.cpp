//
// Created by kenny on 2/5/19.
//
#ifdef KNI_DEBUG
#include <gtest/gtest.h>


#include "nethdrs.h"
#include "../src/hdrs.h"

TEST(NetHeaders, EthernetHeaderReadWrite) {
    const u_char expected_header[] = {
            0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f, 0x20, 0x76,
            0x93, 0x3d, 0x8b, 0x57, 0x08, 0x06,
    };

    kni::eth_header ethHdr;
    kni::getter get(expected_header);
    EXPECT_EQ("20:76:93:3D:8B:57", kni::to_string(get(ethHdr.src)));
    EXPECT_EQ("50:2B:73:DC:54:3F", kni::to_string(get(ethHdr.dst)));
    EXPECT_EQ(ETH_P_ARP, get(ethHdr.type));

    std::unique_ptr<u_char[]> buf(new u_char[sizeof(expected_header)]);
    kni::setter set(buf.get());

    set(ethHdr.src, "20:76:93:3d:8b:57");
    set(ethHdr.dst, "50:2b:73:dc:54:3f");
    set(ethHdr.type, ETH_P_ARP);

    for (int i = 0; i < sizeof(expected_header); ++i)
        EXPECT_EQ(expected_header[i], buf[i]) << "at byte " << i;
}

TEST(NetHeaders, ArpHeaderReadWrite) {
    const u_char expected_header[] = {
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
            0x20, 0x76, 0x93, 0x3d, 0x8b, 0x57, 0xc0, 0xa8,
            0xe1, 0x01, 0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f,
            0xc0, 0xa8, 0xe1, 0xb1
    };

    kni::arp_header arpHdr;
    kni::getter get(expected_header);

    EXPECT_EQ(ARPHRD_ETHER, get(arpHdr.htype));
    EXPECT_EQ(ETH_P_IP, get(arpHdr.ptype));
    EXPECT_EQ(6, get(arpHdr.hlen));
    EXPECT_EQ(4, get(arpHdr.plen));

    EXPECT_EQ("20:76:93:3D:8B:57", kni::to_string(get(arpHdr.sha)));
    EXPECT_EQ("192.168.225.1", kni::to_string(get(arpHdr.spa)));
    EXPECT_EQ("50:2B:73:DC:54:3F", kni::to_string(get(arpHdr.tha)));
    EXPECT_EQ("192.168.225.177", kni::to_string(get(arpHdr.tpa)));
    EXPECT_EQ(ARPOP_REPLY, get(arpHdr.oper));

    std::unique_ptr<u_char[]> buf(new u_char[sizeof(expected_header)]);
    kni::setter set(buf.get());

    set(arpHdr.htype, ARPHRD_ETHER);
    set(arpHdr.ptype, ETH_P_IP);
    set(arpHdr.hlen, 6);
    set(arpHdr.plen, 4);

    set(arpHdr.sha, "20:76:93:3d:8b:57");
    set(arpHdr.spa, "192.168.225.1");
    set(arpHdr.tha, "50:2b:73:dc:54:3f");
    set(arpHdr.tpa, "192.168.225.177");
    set(arpHdr.oper, ARPOP_REPLY);

    for (int i = 0; i < sizeof(expected_header); ++i)
        EXPECT_EQ(expected_header[i], buf[i]) << "at byte " << i;
}

TEST(NetHeaders, Ipv4HeaderReadWrite) {
    const u_char expected_header[] = {
            0x45, 0xd0, 0x00, 0x6d, 0x43, 0x8c, 0x00, 0x00,
            0x40, 0x01, 0xf2, 0x2f, 0xc0, 0xa8, 0xe1, 0xb1,
            0xc0, 0xa8, 0xe1, 0x01
    };

    kni::ipv4_header ipHdr;
    kni::getter get(expected_header);
    EXPECT_EQ(4, get(ipHdr.version));
    EXPECT_EQ(5, get(ipHdr.ihl));
    EXPECT_EQ(0xd0, get(ipHdr.diff));
    EXPECT_EQ(109, get(ipHdr.tot_len));
    EXPECT_EQ(0x438c, get(ipHdr.id));
    EXPECT_EQ(0, get(ipHdr.flags));
    EXPECT_EQ(0, get(ipHdr.frag_off));
    EXPECT_EQ(64, get(ipHdr.ttl));
    EXPECT_EQ(IPPROTO_ICMP, get(ipHdr.proto));
    EXPECT_EQ(0xf22f, get(ipHdr.check));
    EXPECT_EQ("192.168.225.177", kni::to_string(get(ipHdr.src)));
    EXPECT_EQ("192.168.225.1", kni::to_string(get(ipHdr.dst)));

    std::unique_ptr<u_char[]> buf(new u_char[sizeof(expected_header)]);
    kni::setter set(buf.get());

    set(ipHdr.version, 4);
    set(ipHdr.ihl, 5);
    set(ipHdr.diff, 0xd0);
    set(ipHdr.tot_len, 109);
    set(ipHdr.id, 0x438c);
    set(ipHdr.flags, 0);
    set(ipHdr.frag_off, 0x00);
    set(ipHdr.ttl, 64);
    set(ipHdr.proto, IPPROTO_ICMP);
    set(ipHdr.check, 0xf22f);
    set(ipHdr.src, "192.168.225.177");
    set(ipHdr.dst, "192.168.225.1");

    for (int i = 0; i < sizeof(expected_header); ++i)
        EXPECT_EQ(expected_header[i], buf[i]) << "at byte " << i;
}

TEST(NetHeaders, TcpHeaderReadWrite) {
    const u_char expected_header[] = {
            0x9c, 0xfe, 0x01, 0xbb, 0x53, 0xe4, 0x5a, 0xee,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10,
            0x94, 0xc3, 0x00, 0x00,
    };

    kni::tcp_header tcpHdr;
    kni::getter get(expected_header);

    EXPECT_EQ(40190, get(tcpHdr.src));
    EXPECT_EQ(443, get(tcpHdr.dst));
    EXPECT_EQ(0x53e45aee, get(tcpHdr.seq));
    EXPECT_EQ(0x0, get(tcpHdr.ack_seq));
    EXPECT_EQ(10, get(tcpHdr.doff));
    EXPECT_EQ(kni::tcp_header::syn, get(tcpHdr.flags));
    EXPECT_EQ(29200, get(tcpHdr.window));
    EXPECT_EQ(0x94c3, get(tcpHdr.check));
    EXPECT_EQ(0, get(tcpHdr.urg_ptr));

    std::unique_ptr<u_char[]> buf(new u_char[sizeof(expected_header)]);
    kni::setter set(buf.get());
    set(tcpHdr.src, 40190);
    set(tcpHdr.dst, 443);
    set(tcpHdr.seq, 0x53e45aee);
    set(tcpHdr.ack_seq, 0x00000000);
    set(tcpHdr.doff, 10);
    set(tcpHdr.flags, kni::tcp_header::syn);
    set(tcpHdr.window, 29200);
    set(tcpHdr.check, 0x94c3);
    set(tcpHdr.urg_ptr, 0);

    for (int i = 0; i < sizeof(expected_header); ++i)
        EXPECT_EQ(expected_header[i], buf[i]) << "at byte " << i;
}

#endif // KNI_DEBUG
