//
// Created by kenny on 2/14/19.
//

#include <gtest/gtest.h>
#include "nethdrs.h"
#include "lan_info.h"

TEST(Utils, GetGatewayIp) {
    int gateway = kni::get_gateway_ip("wlan0");
    EXPECT_NE(-1, gateway) << strerror(errno);
}