#include <vector>

#ifndef FIREWALL_H_
#define FIREWALL_H_

class Firewall {
private:
    struct Rule {
        int port;
        bool allow;
    };

    std::vector<Rule> rules;

public:
    void add_rule(int port, bool allow);
    bool is_allowed(int port) const;
};

#endif