#include <vector>
#include <iostream>

#ifndef FIREWALL_H_
#define FIREWALL_H_

class Firewall {
private:
    struct Rule {
        int port;
        std::string ip_address;
        int subnet_mask; // Subnet mask length (for example, 24 for /24)
        bool allow;
    };

    std::vector<Rule> rules;

public:
    void add_rule(int port, const std::string& ip_address, int subnet_mask, bool allow);
    bool is_allowed(int port, const std::string& ip_address);
    bool match_subnet(const std::string& ip_address, const std::string& rule_address, int subnet_mask);
};

#endif