#include <iostream>
#include <vector>

#include "firewall.h"

int main() {
    Firewall firewall;

    firewall.add_rule(80, "192.168.1.2", 24, true); 
    firewall.add_rule(443, "192.168.1.3", 24, true);
    firewall.add_rule(22, "192.168.1.4", 24, false);
    firewall.add_rule(8080, "", 0, true);

    int port;
    std::string ip_address;
    std::cout << "Enter a port number: ";
    std::cin >> port;
    std::cout << "Enter an IP address: ";
    std::cin >> ip_address;

    if (firewall.is_allowed(port, ip_address)) {
        std::cout << "Access allowed.\n";
    } else {
        std::cerr << "Access blocked.\n";
    }

    system("pause");
    return 0;
}