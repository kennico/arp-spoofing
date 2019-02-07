//
// Created by kenny on 2/6/19.
//
#ifdef KNI_DEBUG
#include <gtest/gtest.h>

#include "nethdrs.h"
#include "../src/hdrs.h"

TEST(NetHeaders, ArpPacketReadWrite) {
    /* Frame (42 bytes), ARP request */
    const u_char expected_packet[42] = {
            0x20, 0x76, 0x93, 0x3d, 0x8b, 0x57, 0x50, 0x2b, /*  v.=.WP+ */
            0x73, 0xdc, 0x54, 0x3f, 0x08, 0x06, 0x00, 0x01, /* s.T?.... */
            0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x50, 0x2b, /* ......P+ */
            0x73, 0xdc, 0x54, 0x3f, 0xc0, 0xa8, 0xe1, 0xb1, /* s.T?.... */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, /* ........ */
            0xe1, 0x01                                      /* .. */
    };

    kni::arp_packet p;
    kni::getter get(expected_packet);
    EXPECT_EQ("50:2B:73:DC:54:3F", kni::to_string(get(p.ethHdr.src)));
    EXPECT_EQ("20:76:93:3D:8B:57", kni::to_string(get(p.ethHdr.dst)));
    EXPECT_EQ(ETH_P_ARP, get(p.ethHdr.type));

    get.incr(ETHER_HDRLEN);
    EXPECT_EQ(1, get(p.arpHdr.htype));
    EXPECT_EQ(ETH_P_IP, get(p.arpHdr.ptype));
    EXPECT_EQ(6, get(p.arpHdr.hlen));
    EXPECT_EQ(4, get(p.arpHdr.plen));
    EXPECT_EQ(ARPOP_REQUEST, get(p.arpHdr.oper));
    EXPECT_EQ("50:2B:73:DC:54:3F", kni::to_string(get(p.arpHdr.sha)));
    EXPECT_EQ("192.168.225.177", kni::to_string(get(p.arpHdr.spa)));
    EXPECT_EQ("00:00:00:00:00:00", kni::to_string(get(p.arpHdr.tha)));
    EXPECT_EQ("192.168.225.1", kni::to_string(get(p.arpHdr.tpa)));

    std::unique_ptr<u_char[]> buf(new u_char[sizeof(expected_packet)]);
    kni::setter set(buf.get());

    set(p.ethHdr.src, "50:2B:73:DC:54:3F");
    set(p.ethHdr.dst, "20:76:93:3D:8B:57");
    set(p.ethHdr.type, ETH_P_ARP);

    set.incr(ETHER_HDRLEN);
    set(p.arpHdr.htype, 1);
    set(p.arpHdr.ptype, ETH_P_IP);
    set(p.arpHdr.hlen, 6);
    set(p.arpHdr.plen, 4);
    set(p.arpHdr.oper, ARPOP_REQUEST);
    set(p.arpHdr.sha, "50:2B:73:DC:54:3F");
    set(p.arpHdr.spa, "192.168.225.177");
    set(p.arpHdr.tha, "00:00:00:00:00:00");
    set(p.arpHdr.tpa, "192.168.225.1");

    for (int i = 0; i < sizeof(expected_packet); ++i)
        EXPECT_EQ(expected_packet[i], buf[i]) << "at byte " << i;
}

#endif // KNI_DEBUG
