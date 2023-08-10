#include <iostream>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <chrono>
#include <thread>
#include <sstream>

#include "packet.h"
#include "packet_generator.h"
#include "protocol_payload.h"
#include "constants.h"

PacketGenerator::PacketGenerator() {
    srand(static_cast<unsigned>(time(nullptr)));
}

Packet PacketGenerator::generate_random_packet() {
    Packet packet;

    packet.protocol = static_cast<ProtocolType>(rand() % constants::NUM_PROTOCOLS);
    packet.port = rand() % 65536;
    packet.ip_address = generate_random_ip_address();
    packet.payload = generate_random_payload();

    return packet;
}

std::string PacketGenerator::generate_random_ip_address() {
    std::string ip;
    for (int i = 0; i < 4; ++i) {
        ip += std::to_string(rand() % 256);
        if (i < 3) {
            ip += ".";
        }
    }

    return ip;
}

std::string PacketGenerator::generate_random_payload() {
    std::string payload;
    int payload_size = rand() % 256;
    for (int i = 0; i < payload_size; ++i) {
        payload += static_cast<char>(rand() % 256);
    }

    return payload;
}

void PacketGenerator::start_generating_packets(int num_packets, int delay_ms) {
    for (int i = 0; i < num_packets; ++i) {
        Packet packet = generate_random_packet();
        packets.push_back(packet);
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
}

const std::vector<Packet>& PacketGenerator::get_packets() const {
    return packets;
}