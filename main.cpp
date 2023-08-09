#include <iostream>
#include <vector>

#include "firewall.h"

int main() {
    Firewall firewall;

    firewall.add_rule(80, true);
    firewall.add_rule(443, true);
    firewall.add_rule(22, false);

    int port;
    std::cout << "Enter a port number: ";
    std::cin >> port;

    if (firewall.is_allowed(port)) {
        std::cout << "Access allowed.\n";
    } else {
        std::cerr << "Access blocked.\n";
    }

    system("pause");
    return 0;
}