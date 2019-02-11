//
// Created by kenny on 2/11/19.
//
#ifdef KNI_DEBUG

#include <gtest/gtest.h>

#define KNI_DEBUG_TEST

#include "../src/pth-hijack-http.h"

/* Frame (78 bytes) */
const u_char packetVictimSYN[] = {
        0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f, 0x24, 0x1b, /* P+s.T?$. */
        0x7a, 0x10, 0x14, 0xfc, 0x08, 0x00, 0x45, 0x00, /* z.....E. */
        0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, /* .@..@.@. */
        0xe4, 0x94, 0xc0, 0xa8, 0xe1, 0xbb, 0xca, 0x59, /* .......Y */
        0xe9, 0x65, 0xc6, 0x49, 0x00, 0x50, 0x2a, 0x94, /* .e.I.P*. */
        0xf2, 0xc5, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, /* ........ */
        0xff, 0xff, 0xbe, 0x34, 0x00, 0x00, 0x02, 0x04, /* ...4.... */
        0x05, 0xb4, 0x01, 0x03, 0x03, 0x07, 0x01, 0x01, /* ........ */
        0x08, 0x0a, 0x2b, 0xa5, 0x13, 0x0a, 0x00, 0x00, /* ..+..... */
        0x00, 0x00, 0x04, 0x02, 0x00, 0x00              /* ...... */
};

class HijackHttp : public ::testing::Test {
public:
    void SetUp() override {
        EXPECT_EQ(1, inet_pton(AF_INET, "192.168.225.177", &(lan.dev.ip)));

        lan.ipmac_mapping["192.168.225.177"] = {0x50, 0x2b, 0x73, 0xdc, 0x54, 0x3f};
        lan.ipmac_mapping["192.168.225.187"] = {0x24, 0x1b, 0x7a, 0x10, 0x14, 0xfc};
        lan.ipmac_mapping["192.168.225.222"] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

        EXPECT_EQ(1, inet_pton(AF_INET, "192.168.225.222", &(httpd.ip)));
        httpd.port = 80;

        pHijackHttpBase = new kni::hijack_http_base(&lan, httpd);

        kni::ipv4_t ip;
        EXPECT_EQ(1, inet_pton(AF_INET, "192.168.225.187", &ip));
        pHijackHttpBase->add_victim(ip);
    }

protected:

    void SetInputPacket(const u_char *packet, unsigned int len) {
        pHijackHttpBase->cap_packet = packet;
        pHijackHttpBase->cap_info.caplen = len;
        pHijackHttpBase->cap_info.len = len;
    }

    uint16_t CalTcpChecksum() {

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

protected:
    kni::lan_info lan{};
    kni::endpoint_t httpd{};
    kni::hijack_http_base *pHijackHttpBase{nullptr};
};

TEST_F(HijackHttp, HandlePacketVictimSYN) {


    SetInputPacket(packetVictimSYN, sizeof(packetVictimSYN));

    pHijackHttpBase->handle_packet();

    auto packet = pHijackHttpBase->send_buf.get();

    kni::eth_header ethHdr;
    kni::ipv4_header ipHdr;
    kni::tcp_header tcpHdr;

    kni::fields_getter get(packet);

    EXPECT_EQ(lan.ipmac_mapping["192.168.225.177"], get(ethHdr.src));
    EXPECT_EQ(lan.ipmac_mapping["192.168.225.222"], get(ethHdr.dst));

    get.incr(ETHER_HDRLEN);
    EXPECT_EQ("192.168.225.177", kni::to_string(get(ipHdr.src)));
    EXPECT_EQ("192.168.225.222", kni::to_string(get(ipHdr.dst)));
    EXPECT_EQ(0, ipHdr.cal_checksum(get.from()));

    get.incr(get(ipHdr.ihl) * 4);
    EXPECT_EQ(10032, get(tcpHdr.src));
    EXPECT_EQ(80, get(tcpHdr.dst));
    EXPECT_EQ(0, CalTcpChecksum());
}

TEST_F(HijackHttp, HandlePacketHttpdFIN) {

}

TEST_F(HijackHttp, HandlePacketVictimFIN) {

}

TEST_F(HijackHttp, HandlePacketTCPTraffic) {

}

#endif