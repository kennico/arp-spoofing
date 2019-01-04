//
// Created by kenny on 12/29/18.
//

#include <limits>
#include <cstdlib>

#include <pcap.h>
#include "arpspf.h"

int main(int argc, char* argv[]) {
    char errbuf[1024] = {0};
    char *device = pcap_lookupdev(errbuf);
    if (device == nullptr) {
        fatal_error("pcap_lookupdev", errbuf);
    }
    printf("Sniffing on device %s\n", device);

    pcap_t *handle = pcap_open_live(device, 4096, 1, 0, errbuf);
    if (handle == nullptr) {
        fatal_error("pcap_open_live", errbuf);
    }
    int maximum = 10;
    pcap_pkthdr header{};
    for (int i = 0; i < maximum; ++i) {
        const u_char * packet = pcap_next(handle, &header);
        printf("No.%d\n:", i);
        printf("\ttimestamp: %ld.%ld\n", header.ts.tv_sec, header.ts.tv_usec);
        printf("\tlength of portion present: %u\n", header.caplen);
        printf("\tlength of packet off wire: %u\n", header.len);
    }
    pcap_close(handle);
}
