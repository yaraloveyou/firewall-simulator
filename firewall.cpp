#include <iostream>
#include <sstream>

#include "firewall.h"
#include "enums.h"
#include "time.h"

Time GetCurrentTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t current_time = std::chrono::system_clock::to_time_t(now);

    struct tm time_info;

    #ifdef _WIN32
        localtime_s(&time_info, &current_time);
    #else
        localtime(&current_time, &time_info);
    #endif

    Time current_time_struct;
    current_time_struct.hours = time_info.tm_hour;
    current_time_struct.minutes = time_info.tm_min;

    return current_time_struct;
}

void Firewall::add_rule(ProtocolType protocol, int port, const std::string& ip_address, int subnet_mask, bool allow, const Time& time_start, const Time& time_end) {
    rules.push_back({protocol, port, ip_address, subnet_mask, allow, time_start, time_end});
}

bool Firewall::is_allowed(ProtocolType protocol, int port, const std::string& ip_address) {
    Time current_time = GetCurrentTime();

    for (const auto& rule : rules) {
        if (rule.port != port && rule.protocol != protocol) 
            continue;

        if (rule.start_time <= current_time && current_time <= rule.end_time){
            if (rule.subnet_mask == 0) {
                return rule.allow;
            }

            if (match_subnet(ip_address, rule.ip_address, rule.subnet_mask)) {
                return rule.allow;
            }
        } else
            return false;
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