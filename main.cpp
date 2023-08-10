#include <iostream>
#include <vector>

#include "firewall.h"
#include "enums.h"
#include "time.h"

int main() {
    Firewall firewall;

    Time start_HTTP = {8, 0};
    Time end_HTTP = {18, 0};

    Time start_SSH = {0, 0};
    Time end_SSH = {24, 0};

    firewall.add_rule(TCP, 80, "192.168.1.2", 24, true, start_HTTP, end_HTTP); 
    firewall.add_rule(UDP, 443, "192.168.1.3", 24, true, start_HTTP, end_HTTP);
    firewall.add_rule(ICMP, 22, "192.168.1.4", 24, false, start_SSH, end_SSH);
    firewall.add_rule(TCP, 8080, "", 0, true, start_SSH, end_SSH);

    int port;
    std::string ip_address;
    ProtocolType protocol;

    std::cout << "Enter a protocol (0 for TCP, 1 for UDP, 2 for ICMP): ";
    int protocol_choice;
    std::cin >> protocol_choice;
    protocol = static_cast<ProtocolType>(protocol_choice);

    std::cout << "Enter a port number: ";
    std::cin >> port;
    std::cout << "Enter an IP address: ";
    std::cin >> ip_address;

    if (firewall.is_allowed(protocol, port, ip_address)) {
        std::cout << "Access allowed.\n";
    } else {
        std::cerr << "Access blocked.\n";
    }

    firewall.display_logs();

    system("pause");
    return 0;
}