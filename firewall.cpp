#include <iostream>
#include <sstream>
#include <iomanip>

#include "firewall.h"
#include "enums.h"
#include "time.h"
#include "protocol_payload.h"
#include "packet_analyzer.h"
#include "constants.h"

PacketAnalyzer packet_analyzer;

Firewall::Firewall() {
    packet_analyzer.firewall = *this;
}

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

std::string GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t current_time = std::chrono::system_clock::to_time_t(now);

    struct tm time_info;

    #ifdef _WIN32
        localtime_s(&time_info, &current_time);
    #else
        localtime_r(&current_time, &time_info);
    #endif

    std::stringstream ss;
    ss << std::put_time(&time_info, "%Y-%m-%d %H:%M:%S");

    return ss.str();
}

void Firewall::input_rule() {
    ProtocolType protocol;
    int port, subnet_mask;
    std::string ip_address;
    bool allow;
    Time time_start, time_end;

    int protocol_chois;
    std::cout << "Enter a protocol (0 for TCP, 1 for UDP, 2 for ICMP): \b";
    std::cin >> protocol_chois;
    protocol = static_cast<ProtocolType>(protocol_chois);

    std::cout << "Enter an IP address: ";
    std::cin >> ip_address;

    std::cout << "Enter a subner mask: ";
    std::cin >> subnet_mask;

    std::cout << "Enter a port: ";
    std::cin >> port;

    std::cout << "Enter an allow (0 for false, 1 for true): ";
    std::cin >> allow;

    std::cout << "Enter a time start: ";
    std::cin >> time_start.hours >> time_start.minutes;
    
    std::cout << "Enter a time end: ";
    std::cin >> time_end.hours >> time_end.minutes;

    add_rule(protocol, port, ip_address, subnet_mask, allow, time_start, time_end);
}

void Firewall::add_rule(ProtocolType protocol, int port, const std::string& ip_address, int subnet_mask, bool allow, const Time& time_start, const Time& time_end) {
    rules.push_back({protocol, port, ip_address, subnet_mask, allow, time_start, time_end});
}

void Firewall::add_log_entry(const LogEntry& log_entry) {
    logs.push_back(log_entry);
}

void Firewall::add_log_attack(const Packet& packet, const std::string& attack_type) {
    std::string timestamp = GetCurrentTimestamp();

    LogAttack log_entry = {
        timestamp, 
        packet.ip_address, 
        packet.port, 
        packet.protocol, 
        attack_type
    };

    logs_attack.push_back(log_entry);
}

bool Firewall::is_allowed(const Packet& packet) {
    Time current_time = GetCurrentTime();
    
    size_t expected_payload_size = ProtocolPayload().get_expected_payload_size(packet.protocol);

    if (packet_analyzer.is_buffer_overflow_attack(packet, expected_payload_size)) {
        add_log_entry({GetCurrentTimestamp(), "Blocked", packet.protocol, packet.port, packet.ip_address});
        return false;
    }

    if (packet_analyzer.is_ddos_attack(packet, constants::MAX_REQUESTS_THRESHOLD)) {
        add_log_entry({GetCurrentTimestamp(), "Blocked", packet.protocol, packet.port, packet.ip_address});
        return false;
    }

    if (packet_analyzer.is_port_scanning(packet)) {
        add_log_entry({GetCurrentTimestamp(), "Blocked", packet.protocol, packet.port, packet.ip_address});
        return false;
    }

    for (const auto& rule : rules) {
        std::string ip_mask = packet.ip_address + "/" + std::to_string(rule.subnet_mask);
        if (rule.port != packet.port && rule.protocol != packet.protocol) 
            continue;

        if (!rule.ip_address.empty() && rule.port != packet.port)
            continue;

        if (rule.start_time <= current_time && current_time <= rule.end_time){
            if (rule.subnet_mask == 0) {
                add_log_entry({GetCurrentTimestamp(), (rule.allow? "Allowed" : "Blocked"), packet.protocol, packet.port, ip_mask});
                return rule.allow;
            }

            if (match_subnet(packet.ip_address, rule.ip_address, rule.subnet_mask)) {
                add_log_entry({GetCurrentTimestamp(), (rule.allow? "Allowed" : "Blocked"), packet.protocol, packet.port, ip_mask});
                return rule.allow;
            }
        } else {
            add_log_entry({GetCurrentTimestamp(), (!rule.allow? "Allowed" : "Blocked"), packet.protocol, packet.port, ip_mask});
            return !rule.allow;
        }
    }
    add_log_entry({GetCurrentTimestamp(), "Allowed", packet.protocol, packet.port, packet.ip_address});
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

    uint32_t subnet_mask_binary = 0xFFFFFFFF << (32 - subnet_mask);

    uint32_t ip_binary = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];
    uint32_t rule_binary = (rule_parts[0] << 24) | (rule_parts[1] << 16) | (rule_parts[2] << 8) | rule_parts[3];

    ip_binary &= subnet_mask_binary;
    rule_binary &= subnet_mask_binary;

    return (ip_binary & subnet_mask_binary) == (rule_binary & subnet_mask_binary);
}

std::string GetProtocolName(ProtocolType protocol) {
    switch (protocol) {
        case ProtocolType::TCP:
            return "TCP";
        case ProtocolType::UDP:
            return "UDP";
        case ProtocolType::ICMP:
            return "ICMP";
        default:
            return "Unknown";
    }
}

void Firewall::display_logs() {
    std::cout << std::left << std::setw(20) << "Timestamp"
              << std::setw(12) << "Event Type"
              << std::setw(10) << "Protocol"
              << std::setw(10) << "Port"
              << "IP Address" << std::endl;

    for (const auto& log : logs) {
        std::cout << std::left << std::setw(20) << log.timestamp
                  << std::setw(12) << log.event_type
                  << std::setw(10) << GetProtocolName(log.protocol)
                  << std::setw(10) << log.port
                  << log.ip_address << std::endl;
    }
}

void Firewall::display_rules() {
    std::cout << std::left << std::setw(10) << "Protocol"
              << std::setw(10) << "Port"
              << std::setw(15) << "IP Address"
              << std::setw(12) << "Subnet Mask"
              << std::setw(10) << "Allow"
              << std::setw(15) << "Start Time"
              << "End Time" << std::endl;

    for (const auto& rule : rules) {
        std::cout << std::left << std::setw(10) << GetProtocolName(rule.protocol)
                  << std::setw(10) << rule.port
                  << std::setw(15) << rule.ip_address
                  << std::setw(12) << rule.subnet_mask
                  << std::setw(10) << (rule.allow ? "Allow" : "Block")
                  << std::setw(15) << rule.start_time.to_string()
                  << rule.end_time.to_string() << std::endl;
    }
}

void Firewall::display_logs_attack() {
        std::cout << std::left << std::setw(20) << "Timestamp"
              << std::setw(12) << "Event Type"
              << std::setw(10) << "Protocol"
              << std::setw(10) << "Port"
              << "IP Address" << std::endl;

    for (const auto& log : logs_attack) {
        std::cout << std::left << std::setw(20) << log.timestamp
                  << std::setw(10) << GetProtocolName(log.protocol)
                  << std::setw(10) << log.port
                  << log.ip_address
                  << std::setw(40) << log.attack_type << std::endl;
    }
}