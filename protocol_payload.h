#include <vector>

#include "enums.h"

#ifndef PROTOCOL_PAYLOAD_H_
#define PROTOCOL_PAYLOAD_H_

class ProtocolPayload{
private:
    struct ProtocolPayloadSize {
        ProtocolType protocol;
        size_t expected_size;
    };

    static const size_t DEFAULT_EXPECTED_SIZE = 512;

    std::vector<ProtocolPayloadSize> protocol_payload_sizes = {
        {ProtocolType::TCP, 1024},
        {ProtocolType::UDP, 512}
    };

public:
    size_t get_expected_payload_size(ProtocolType protocol) {
        for (const auto& size_info : protocol_payload_sizes) {
            if (size_info.protocol == protocol)
                return size_info.expected_size;
        }

        return DEFAULT_EXPECTED_SIZE;
    }
};

#endif