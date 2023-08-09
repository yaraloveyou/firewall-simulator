#include <vector>
#include <iostream>

#include "enums.h"

#ifndef FIREWALL_H_
#define FIREWALL_H_

class Firewall {
private:
    struct Rule {
        ProtocolType protocol;
        int port;
        std::string ip_address;
        int subnet_mask;
        bool allow;
    };

    std::vector<Rule> rules;

public:
    void add_rule(ProtocolType protocol, int port, const std::string& ip_address, int subnet_mask, bool allow);
    bool is_allowed(ProtocolType protocol, int port, const std::string& ip_address);
    bool match_subnet(const std::string& ip_address, const std::string& rule_address, int subnet_mask);
};

#endif