//
// Created by kenny on 1/27/19.
//

#include <gtest/gtest.h>
#include <arpspf.h>
#include "fields.h"

TEST(ModifyPacket, BuildArpPacket) {

    u_char buf[ETHER_HDRLEN + ARP_HDRLEN] = {0};
    char ebuf[PCAP_ERRBUF_SIZE] = {0};

    kni::arp_io_packet arp(ebuf);
    arp.set_input(buf);

    auto &arpHdr = arp.arpHdr;
    auto &ethHdr = arp.ethHdr;

    ethHdr.dst = "50:2b:73:dc:54:3f";
    ethHdr.src = "20:76:93:3d:8b:57";

    arpHdr.sha = "20:76:93:3d:8b:57";
    arpHdr.spa = "192.168.225.1";
    arpHdr.tha = "50:2b:73:dc:54:3f";
    arpHdr.tpa = "192.168.225.177";
    arpHdr.oper = ARPOP_REPLY;

    /* Frame (42 bytes) */
    unsigned char pkt24[42] = {
            0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f, 0x20, 0x76, /* P+s.T? v */
            0x93, 0x3d, 0x8b, 0x57, 0x08, 0x06, 0x00, 0x01, /* .=.W.... */
            0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x20, 0x76, /* ...... v */
            0x93, 0x3d, 0x8b, 0x57, 0xc0, 0xa8, 0xe1, 0x01, /* .=.W.... */
            0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f, 0xc0, 0xa8, /* P+s.T?.. */
            0xe1, 0xb1                                      /* .. */
    };

    for (int i = 0; i < ETHER_HDRLEN + ARP_HDRLEN; ++i)
        EXPECT_EQ(pkt24[i], arp.content()[i]) << "byte at " << i;

}
