#include <iostream>
#include <sstream>

#include "firewall.h"

void Firewall::add_rule(int port, const std::string& ip_address, int subnet_mask, bool allow) {
    rules.push_back({port, ip_address, subnet_mask, allow});
}

bool Firewall::is_allowed(int port, const std::string& ip_address) {
    for (const auto& rule : rules) {
        if (rule.port != port) 
            continue;

        if (rule.subnet_mask == 0) {
            return rule.allow;
        }

        if (match_subnet(ip_address, rule.ip_address, rule.subnet_mask)) {
            return rule.allow;
        }
    }

    return true;
}

bool Firewall::match_subnet(const std::string& ip_address, const std::string& rule_address, int subnet_mask) {
    std::vector<int> ip_parts, rule_parts;
    std::istringstream ip_stream(ip_address);
    std::string ip_part;

    while (std::getline(ip_stream, ip_part, '.')) {
        ip_parts.push_back(std::stoi(ip_part));
    }

    std::istringstream rule_stream(rule_address);
    std::string rule_part;

    while (std::getline(rule_stream, rule_part, '.')) {
        rule_parts.push_back(std::stoi(rule_part));
    }

    // mask to binary
    uint32_t subnet_mask_binary = 0xFFFFFFFF << (32 - subnet_mask);

    // ip to binary
    uint32_t ip_binary = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_part[3];
    uint32_t rule_binary = (rule_parts[0] << 24) | (rule_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];

    ip_binary &= subnet_mask_binary;
    rule_binary &= subnet_mask_binary;

    return ip_binary == rule_binary;
}