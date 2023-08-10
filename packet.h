#include "enums.h"
#include <iostream>

#ifndef PACKET_H_
#define PACKET_H_

struct Packet {
    ProtocolType protocol;
    int port;
    std::string ip_address;
    std::string payload;
};

#endif