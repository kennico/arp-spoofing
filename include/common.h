//
// Created by kenny on 12/29/18.
//

#pragma once

#include <pcap.h>
#include <string>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>

void fatal_error(const char* src, const char* err);
int mac_pton(const char*, void*);
char* mac_ntop(const void*, char*, socklen_t);
void get_gateway_ip(void*, size_t);
void get_gateway_mac(void*, size_t);

#define ETHER_HDR_LEN 14
#define MAC_ADDRLEN 6
#define ARP_HDR_LEN 28

const u_short ETHERNET_TYPE = 0x0806;
const u_short ARP_PTYPE_IPV4 = 0x0800;
const u_short ARP_HTYPE_ETHERNET = 0x0001;
const u_short ARP_OPER_REPLY = 0x0002;

struct ether_hdr {
    u_char dst_addr[MAC_ADDRLEN];
    u_char src_addr[MAC_ADDRLEN];
    u_short type;
} __attribute__((packed));

struct arp_hdr {
    u_short htype;
    u_short ptype;
    u_char hlen;
    u_char plen;
    u_short oper;
    u_char sha[MAC_ADDRLEN];
    u_int spa;
    u_char tha[MAC_ADDRLEN];
    u_int tpa;
} __attribute__((packed));

std::string to_string(const sockaddr& addr);
std::string to_string_null(const sockaddr* addr);