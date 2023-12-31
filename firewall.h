#include <vector>
#include <iostream>

#include "enums.h"
#include "time.h"
#include "log.h"
#include "packet.h"

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
        Time start_time; 
        Time end_time;
    };

    std::vector<Rule> rules;
    std::vector<LogEntry> logs;
    std::vector<LogAttack> logs_attack;

public:
    Firewall();
    void add_rule(ProtocolType protocol, int port, const std::string& ip_address, int subnet_mask, bool allow, const Time& start_time, const Time& end_time);
    bool is_allowed(const Packet& packet);
    bool match_subnet(const std::string& ip_address, const std::string& rule_address, int subnet_mask);
    void add_log_entry(const LogEntry& log_entry);
    void display_logs();
    void display_logs_attack();
    void display_rules();
    void input_rule();

    void add_log_attack(const Packet& packet, const std::string& attack_type);
    bool is_buffer_overflow_attack(const Packet& packet, size_t expected_payload_size);
};

#endif