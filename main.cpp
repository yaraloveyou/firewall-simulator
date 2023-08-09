#include <iostream>
#include <vector>

#include "firewall.h"
#include "enums.h"

int main() {
    Firewall firewall;

    firewall.add_rule(TCP, 80, "192.168.1.2", 24, true); 
    firewall.add_rule(UDP, 443, "192.168.1.3", 24, true);
    firewall.add_rule(ICMP, 22, "192.168.1.4", 24, false);
    firewall.add_rule(TCP, 8080, "", 0, true);

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

    system("pause");
    return 0;
}