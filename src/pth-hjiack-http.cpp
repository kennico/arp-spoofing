//
// Created by kenny on 2/1/19.
//
#include "arpspf.h"
#include "pth-args.h"
#include "hdrs.h"

using namespace kni;

void *routine_start_hijack_http(void *ptr) {
//    auto args = (pthargs_hijack_http *) ptr;
//    auto netdb = args->netdb;
//
//    std::unique_ptr<char[]> errbuf(new char[PCAP_ERRBUF_SIZE]);
//    auto handle = pcap_open_live(netdb->devname.c_str(), 4096, 1, 0, errbuf.get());
//
//    if (handle == nullptr) {
//        KNI_LOG_ERROR("failed to open device \"%s\": %s", netdb->devname, errbuf.get());
//        return nullptr;
//    } else {
//        KNI_LOG_DEBUG("device \"%s\" opened successfully.", netdb->devname.c_str());
//    }
//
//    constexpr const uint32_t BASIC_HDRLEN = ETHER_HDRLEN + IPV4_MAX_HDRLEN + TCP_MAX_HDRLEN;
//    std::unique_ptr<u_char[]> basicHdrBuf(new u_char[BASIC_HDRLEN]);
//
//    modifypkt_tcp hdrs;
//
////    std::queue<uint16_t> port_que;
////    std::set<uint16_t> used_port;
//
//    while (args->to_be_running) {
//        pcap_pkthdr pkthdr; // NOLINT
//        auto packet = pcap_next(handle, &pkthdr);
//        if (packet == nullptr) {
//            KNI_LOG_ERROR("pcap_next: %s", pcap_geterr(handle));
//        }
//
//        memcpy(basicHdrBuf.get(), packet, std::min(BASIC_HDRLEN, pkthdr.len));
//        hdrs.update_input(basicHdrBuf.get());
//
//        if ((uint16_t) hdrs.ethHdr.type == ETH_P_IP) {
////            if (hdrs.ipHdr.dst)
//        }
//    }
    return nullptr
}
