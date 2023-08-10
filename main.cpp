#include <iostream>
#include <vector>

#include "firewall.h"
#include "enums.h"
#include "time.h"
#include "packet.h"
#include "packet_generator.h"

int main() {
    Firewall firewall;

    Time start_HTTP = {8, 0};
    Time end_HTTP = {18, 0};

    Time start_SSH = {0, 0};
    Time end_SSH = {24, 0};

    firewall.add_rule(TCP, 80, "192.168.1.2", 26, true, start_HTTP, end_HTTP); 
    firewall.add_rule(UDP, 443, "192.168.1.3", 24, true, start_HTTP, end_HTTP);
    firewall.add_rule(ICMP, 22, "192.168.1.4", 24, false, start_SSH, end_SSH);
    firewall.add_rule(TCP, 8080, "", 0, true, start_SSH, end_SSH);

    PacketGenerator generator;
    generator.start_generating_packets(1000, 1);
    const std::vector<Packet>& packets = generator.get_packets();

    for (const auto& packet : packets) {
        firewall.is_allowed(packet);
    }

    firewall.display_logs();

    system("pause");
    return 0;
}