#include <iostream>
#include "enums.h"

#ifndef LOG_H_
#define LOG_H_

struct LogEntry {
    std::string timestamp;
    std::string event_type;
    ProtocolType protocol;
    int port;
    std::string ip_address;
};

struct LogAttack {
    std::string timestamp;
    std::string ip_address;
    int port;
    ProtocolType protocol;
    std::string attack_type;
};

#endif