//
// Created by kenny on 1/4/19.
//

#pragma once

#include "pkt.h"

int get_gateway_ip(const char *dev=NULL, int attempts=5, int ms=50);
