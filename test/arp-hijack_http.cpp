//
// Created by kenny on 2/11/19.
//
#if 0
#include <gtest/gtest.h>

//#define KNI_DEBUG_TEST_PREVENT_SEND
#include "../src/arp-hijack.h"


/* Frame (74 bytes) based on pkt28
 * 192.168.225.187:60074 -> 74.114.90.46:80
 */
static const unsigned char victimSYN[] = {
        0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f, 0x20, 0x76,
        0x93, 0x3d, 0x8b, 0x57, 0x08, 0x00, 0x45, 0x00, /* s.T?..E. */
        0x00, 0x3c, 0x93, 0x6e, 0x40, 0x00, 0x40, 0x06, /* .<.n@.@. */
        0x60, 0x49, 0xc0, 0xa8, 0xe1, 0xbb, 0x4a, 0x72, /* `S....Jr */
        0x5a, 0x2e, 0xea, 0xaa, 0x00, 0x50, 0x7b, 0x8d, /* Z....P{. */
        0xf2, 0xdd, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, /* ........ */
        0x72, 0x10, 0xd3, 0x9b, 0x00, 0x00, 0x02, 0x04, /* r....... */
        0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x36, /* .......6 */
        0x61, 0xb3, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, /* a....... */
        0x03, 0x07                                      /* .. */
};

/* Frame (58 bytes) based on pkt32
 * 192.168.225.222:80 -> 192.168.225.177:10032
 */
static const unsigned char httpdACK[] = {
        0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x08, 0x00, 0x45, 0x00, /* .=.W..E. */
        0x00, 0x2c, 0xad, 0x67, 0x40, 0x00, 0xfe, 0x06, /* .,.g@... */
        0x8a, 0x82, 0xc0, 0xa8, 0xe1, 0xde, 0xc0, 0xa8, /* .iJrZ... */
        0xe1, 0xb1, 0x00, 0x50, 0x27, 0x30, 0x0d, 0xda, /* ...P.... */
        0x55, 0x46, 0x7b, 0x8d, 0xf2, 0xde, 0x60, 0x12, /* UF{...`. */
        0x04, 0x00, 0x57, 0xdc, 0x00, 0x00, 0x02, 0x04, /* ...H.... */
        0x04, 0x00                                      /* .. */
};

/* Frame (54 bytes) based on pkt39
 * 192.168.225.187:60074 -> 74.114.90.46:80
 */
static const unsigned char victimFIN[] = {
        0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f, 0x20, 0x76,
        0x93, 0x3d, 0x8b, 0x57, 0x08, 0x00, 0x45, 0x00, /* s.T?..E. */
        0x00, 0x28, 0x93, 0x73, 0x40, 0x00, 0x40, 0x06, /* .(.s@.@. */
        0x60, 0x58, 0xc0, 0xa8, 0xe1, 0xbb, 0x4a, 0x72, /* `b....Jr */
        0x5a, 0x2e, 0xea, 0xaa, 0x00, 0x50, 0x7b, 0x8d, /* Z....P{. */
        0xf5, 0x31, 0x0d, 0xda, 0x55, 0xe2, 0x50, 0x11, /* .1..U.P. */
        0x76, 0x00, 0x33, 0x58, 0x00, 0x00              /* v.3b.. */
};

/* Frame (54 bytes) based on pkt40
 * 192.168.225.222:80 -> 192.168.225.177:10032
 */
static const unsigned char httpdRST[] = {
        0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x08, 0x00, 0x45, 0x00, /* .=.W..E. */
        0x00, 0x28, 0xad, 0x6a, 0x40, 0x00, 0xfe, 0x06, /* .(.j@... */
        0x8a, 0x83, 0xc0, 0xa8, 0xe1, 0xde, 0xc0, 0xa8, /* .jJrZ... */
        0xe1, 0xb1, 0x00, 0x50, 0x27, 0x30, 0x0d, 0xda, /* ...P.... */
        0x55, 0xe2, 0x7b, 0x8d, 0xf5, 0x31, 0x50, 0x04, /* U.{..1P. */
        0x04, 0x00, 0x6b, 0x03, 0x00, 0x00              /* ...o.. */
};

class HijackHttp : public ::testing::Test {
public:
    void SetUp() override {
        EXPECT_EQ(1, inet_pton(AF_INET, "192.168.225.177", &(lan.dev.ip)));

        lan.ipmac_mapping["192.168.225.177"] = {0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f};    // dev
        lan.ipmac_mapping["192.168.225.187"] = {0x20, 0x76, 0x93, 0x3d, 0x8b, 0x57};    // victim
        lan.ipmac_mapping["192.168.225.222"] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};    // httpd

        EXPECT_EQ(1, inet_pton(AF_INET, "192.168.225.222", &(httpd.ip)));
        httpd.port = 80;

        pHijackHttpBase = new kni::hijack_http(&lan, httpd);

        kni::ipv4_t ip;
        EXPECT_EQ(1, inet_pton(AF_INET, "192.168.225.187", &ip));
        pHijackHttpBase->add_victim(ip);
    }

    void TearDown() override {
        delete pHijackHttpBase;
        pHijackHttpBase = nullptr;
    }

protected:

    template<size_t N>
    void SetInputPacket(const u_char (&packet)[N]) {
        SetInputPacket(packet, static_cast<unsigned int>(N));
    }

    void SetInputPacket(const u_char *packet, unsigned int len) {
        pHijackHttpBase->cap_packet = packet;
        pHijackHttpBase->cap_info.caplen = len;
        pHijackHttpBase->cap_info.len = len;
    }

    uint16_t SendBufTcpCalChecksum() {

        kni::pseudo_ipv4 pseudo;
        u_char buf[PSEUDO_IPV4_HDRLEN];
        kni::fields_setter set(buf);

        kni::fields_getter get(pHijackHttpBase->send_buf.get());
        get.incr(ETHER_HDRLEN);
        kni::ipv4_header ipHdr;

        set(pseudo.src, get(ipHdr.src));
        set(pseudo.dst, get(ipHdr.dst));
        set(pseudo.rsv, 0);
        set(pseudo.proto, IPPROTO_TCP);

        auto ipHdrLen = 4 * get(ipHdr.ihl);
        set(pseudo.tcp_len, get(ipHdr.tot_len) - ipHdrLen);

        kni::tcp_header tcpHdr;
        return tcpHdr.cal_checksum(get.incr(ipHdrLen).from(), buf);
    }

    uint16_t SendBufIpv4CalChecksum() {
        return pHijackHttpBase->ipHdr.cal_checksum(pHijackHttpBase->send_buf.get() + ETHER_HDRLEN);
    }

    void DoExpectSendBufferTcp(const std::string &senderIp, const std::string &receiverIp, kni::port_t senderPort,
                               kni::port_t receiverPort) {
        auto packet = pHijackHttpBase->send_buf.get();

        kni::eth_header ethHdr;
        kni::ipv4_header ipHdr;
        kni::tcp_header tcpHdr;

        kni::fields_getter get(packet);

        EXPECT_EQ(lan.ipmac_mapping[senderIp], get(ethHdr.src));
        EXPECT_EQ(lan.ipmac_mapping[receiverIp], get(ethHdr.dst));

        get.incr(ETHER_HDRLEN);
        EXPECT_EQ(senderIp, kni::to_string(get(ipHdr.src)));
        EXPECT_EQ(receiverIp, kni::to_string(get(ipHdr.dst)));
        EXPECT_EQ(0, ipHdr.cal_checksum(get.from()));

        get.incr(get(ipHdr.ihl) * 4);
        EXPECT_EQ(senderPort, get(tcpHdr.src));
        EXPECT_EQ(receiverPort, get(tcpHdr.dst));
        EXPECT_EQ(0, SendBufTcpCalChecksum());
    }

protected:
    kni::lan_info lan{};
    kni::endpoint_t httpd{};
    kni::hijack_http *pHijackHttpBase{nullptr};
};

TEST_F(HijackHttp, HandlePacketVictimSYN) {
    SetInputPacket(victimSYN);
    pHijackHttpBase->handle_packet();
    DoExpectSendBufferTcp("192.168.225.177", "192.168.225.222", 10032, 80);
}

TEST_F(HijackHttp, HandlePacket) {
    SetInputPacket(victimSYN);
    pHijackHttpBase->handle_packet();
    DoExpectSendBufferTcp("192.168.225.177", "192.168.225.222", 10032, 80);
    EXPECT_EQ(10032 + 1, pHijackHttpBase->assign_fake_port());

    SetInputPacket(httpdACK);
    pHijackHttpBase->handle_packet();
    DoExpectSendBufferTcp("74.114.90.46", "192.168.225.187", 80, 60074);
    EXPECT_EQ(10032 + 2, pHijackHttpBase->assign_fake_port());

    SetInputPacket(victimFIN);
    pHijackHttpBase->handle_packet();
    DoExpectSendBufferTcp("192.168.225.177", "192.168.225.222", 10032, 80);
    EXPECT_EQ(10032 + 3, pHijackHttpBase->assign_fake_port());

    SetInputPacket(httpdRST);
    pHijackHttpBase->handle_packet();
    DoExpectSendBufferTcp("74.114.90.46", "192.168.225.187", 80, 60074);

    EXPECT_EQ(10032, pHijackHttpBase->assign_fake_port());
}


TEST_F(HijackHttp, HandlePacketVictimSYNRetransmission) {
    for (int i = 0; i < 5; ++i) {
        SetInputPacket(victimSYN);
        pHijackHttpBase->handle_packet();
        DoExpectSendBufferTcp("192.168.225.177", "192.168.225.222", 10032, 80);
        EXPECT_EQ(10032 + i + 1, pHijackHttpBase->assign_fake_port());
    }
}


TEST_F(HijackHttp, TcpIpCalChecksum) {
    memcpy(pHijackHttpBase->send_buf.get(), victimSYN, sizeof(victimSYN));
    EXPECT_EQ(0, SendBufIpv4CalChecksum());
    EXPECT_EQ(0, SendBufTcpCalChecksum());

    memcpy(pHijackHttpBase->send_buf.get(), httpdACK, sizeof(httpdACK));
    EXPECT_EQ(0, SendBufIpv4CalChecksum());
    EXPECT_EQ(0, SendBufTcpCalChecksum());

    memcpy(pHijackHttpBase->send_buf.get(), victimFIN, sizeof(victimFIN));
    EXPECT_EQ(0, SendBufIpv4CalChecksum());
    EXPECT_EQ(0, SendBufTcpCalChecksum());

    memcpy(pHijackHttpBase->send_buf.get(), httpdRST, sizeof(httpdRST));
    EXPECT_EQ(0, SendBufIpv4CalChecksum());
    EXPECT_EQ(0, SendBufTcpCalChecksum());
}

#endif