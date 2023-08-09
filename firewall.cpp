#include "firewall.h"

void Firewall::add_rule(int port, bool allow) {
    rules.push_back({port, allow});
}

bool Firewall::is_allowed(int port) const {
    for (const auto& rule: rules) {
        if (rule.port == port)
            return rule.allow;
    }

    return true;
}