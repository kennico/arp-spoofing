//
// Created by kenny on 1/3/19.
//

#include <cstring>
#include <arpa/inet.h>
#include <iostream>

#include "arpspf.h"



int main(int argc, char* argv[]) {
    auto ip = get_gateway_ip("wlx502b73dc543f");
    if (ip == -1) {
        perror("");
        return 1;
    }
    char buf[32] = {};
    inet_ntop(AF_INET, &ip, buf, sizeof(buf));

    std::cout << buf << std::endl;
}




