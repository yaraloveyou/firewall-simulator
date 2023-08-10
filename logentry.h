#include <iostream>
#include "enums.h"

#ifndef LOGENTRY_H_
#define LOGENTRY_H_

struct LogEntry {
    std::string timestamp;
    std::string event_type;
    ProtocolType protocol;
    int port;
    std::string ip_address;
};

#endif