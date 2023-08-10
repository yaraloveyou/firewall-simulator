#include <unordered_set>
#include <iostream>
#include <chrono>

#include "firewall.h"
#include "packet_analyzer.h"

// PacketAnalyzer::PacketAnalyzer(Firewall& firewall) {
//     m_firewall = firewall;
// }

bool PacketAnalyzer::is_buffer_overflow_attack(const Packet& packet, size_t expected_payload_size) {
    if (packet.payload.size() > expected_payload_size) {
        firewall.add_log_attack(packet, "Buffer Overflow Attack");
        return true;
    }

    return false;
}

bool PacketAnalyzer::is_ddos_attack(const Packet& packet, size_t threshold) {
    auto now = std::chrono::steady_clock::now();

    if (now - last_reset_time[packet.ip_address] >= std::chrono::minutes(1)) {
        source_packet_count[packet.ip_address] = 0;
        last_reset_time[packet.ip_address] = now;
    }

    source_packet_count[packet.ip_address]++;

    if (source_packet_count[packet.ip_address] > threshold) {
        firewall.add_log_attack(packet, "DDoS Attack");
        return true;
    }

    return false;
}

bool PacketAnalyzer::is_port_scanning(const Packet& packet) {
    std::unordered_set<int>& prev_ports = previos_ports[packet.ip_address];

    if (prev_ports.find(packet.port) != prev_ports.end()) {
        firewall.add_log_attack(packet, "Port scanning");
        return true;
    }
    
    prev_ports.insert(packet.port);
    return false;
}