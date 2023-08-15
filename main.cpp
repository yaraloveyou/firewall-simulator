#include <iostream>
#include <vector>
#include <string>
#ifdef _WIN32
#include <conio.h>
#define CLEAR_SCREEN "cls"
#else
#include <termios.h>
#include <unistd.h>
#define CLEAR_SCREEN "clear"
#endif

#include "firewall.h"
#include "enums.h"
#include "time.h"
#include "packet.h"
#include "packet_generator.h"

int main() {
    Firewall firewall;

    std::vector<std::string> options = {"Add rule", "Browsing rules", "Viewing logs", "View attack logs"};
    int selected_option = 0;
    std::vector<Packet> packets;

    while (true) {
        PacketGenerator packet_generator;
        packet_generator.start_generating_packets(5, 0);
        system(CLEAR_SCREEN);
        for (int i = 0; i < options.size(); ++i) {
            if (selected_option == i) {
                std::cout << "> " << options[i] << std::endl;
            } else {
                std::cout << "  " << options[i] << std::endl;
            }
        }

        int key = _getch();
        switch (key) {
            case 72:
                selected_option = (selected_option - 1 + options.size()) % options.size();
                break;
            case 80:
                selected_option = (selected_option + 1) % options.size();
            break;
            case 13:
                system(CLEAR_SCREEN);
                if (selected_option == 0) {
                    firewall.input_rule();
                }
                else if (selected_option == 1) {
                    firewall.display_rules();
                }
                else if (selected_option == 2) {
                    packets = packet_generator.get_packets();
                    for (const auto& packet : packets)
                        firewall.is_allowed(packet);
                    firewall.display_logs();
                } else if (selected_option == 3) {
                    firewall.display_logs_attack();
                }
                    
                system("pause");
            break;
        }
    }

    system("pause");
    return 0;
}