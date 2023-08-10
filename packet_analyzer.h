#include <iostream>
#include <unordered_map>
#include <unordered_set>

#include "packet.h"
#include "firewall.h"

#ifndef PACKET_ANALYZER_H_
#define PACKET_ANALYZER_H_

class PacketAnalyzer {
private:
    std::unordered_map<std::string, std::unordered_set<int>> previos_ports;
    std::unordered_map<std::string, int> source_packet_count;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_reset_time;

public:
    Firewall firewall;
    PacketAnalyzer() {}
    bool is_buffer_overflow_attack(const Packet& packet, size_t expected_payload_size);
    bool is_ddos_attack(const Packet& packet, size_t threshold);
    bool is_port_scanning(const Packet& packet);
};

#endif