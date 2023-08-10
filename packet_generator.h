#include "packet.h"

class PacketGenerator {
private:
    std::vector<Packet> packets;
public:
    PacketGenerator();
    Packet generate_random_packet();
    std::string generate_random_ip_address();
    std::string generate_random_payload();
    void start_generating_packets(int num_packets, int delay_ms);
    const std::vector<Packet>& get_packets() const;
};