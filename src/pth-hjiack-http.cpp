//
// Created by kenny on 2/1/19.
//
#include "arpspf.h"
#include "pth-args.h"
#include "fake-port.h"
#include "hdrs.h"

using namespace kni;


/**
 * httpd listens on the same interface
 *
 * @param ptr
 * @return
 */
void *routine_start_hijack_http(void *ptr) {

    auto args = (pthargs_hijack_http *) ptr;
    auto netdb = args->netdb;
    auto dev = &netdb->devinfo;

    std::unique_ptr<char[]> errbuf(new char[PCAP_ERRBUF_SIZE]);
    auto handle = pcap_open_live(netdb->devname.c_str(), 4096, 1, 0, errbuf.get());

    if (handle == nullptr) {
        KNI_LOG_ERROR("failed to open device \"%s\": %s", netdb->devname, errbuf.get());
        return nullptr;
    } else {
        KNI_LOG_DEBUG("device \"%s\" opened successfully.", netdb->devname.c_str());
    }

    eth_header eth;
    ipv4_header ip;
    tcp_header tcp;

    while (args->to_be_running) {
        pcap_pkthdr pkthdr; // NOLINT
        auto packet = pcap_next(handle, &pkthdr);
        if (packet == nullptr) {
            KNI_LOG_ERROR("pcap_next() returns NULL: %s", pcap_geterr(handle));
            continue;
        }

        fields_getter get(packet);

        // Does it contains an IPv4 header?
        if (get(eth.type) == ETH_P_IP) {
            // Does it contains a TCP header?
            if (get.incr(ETHER_HDRLEN)(ip.proto) == IPPROTO_TCP) {
                auto sender_ip = get(ip.src);
                get.incr(static_cast<size_t>(get(ip.ihl) * 4));

                if (sender_ip == args->victim_ip && get(tcp.dst) == 80) {
                    // TODO Misled packet

                } else if (sender_ip == dev->ip && get(tcp.src) == args->httpd) {
                    // TODO sent by httpd

                }
            }

        }
    }
    return nullptr;
}
