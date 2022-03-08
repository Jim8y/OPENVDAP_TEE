//
// Created by compass on 9/15/19.
//

#include <Helper.h>
#include <vector>

std::string Helper::strip(const std::string &s) {
    return (s.size() >= 2 && s[1] == 'x') ? s.substr(2) : s;
}

std::vector<uint8_t> Helper::to_bytes(const std::string &_s) {
    auto s = strip(_s);
    const size_t byte_len = (s.size() + 1) / 2; // round up
    std::vector<uint8_t> v(byte_len);
    // Handle odd-length strings
    size_t n = 0;
    if (s.size() % 2 != 0) {
        v[0] = static_cast<uint8_t>(strtoul(s.substr(0, 1).c_str(), nullptr, 16));
        ++n;
    }

    auto x = n;
    for (auto i = n; i < byte_len; ++i, x += 2) {
        v[i] = static_cast<uint8_t>(strtoul(s.substr(x, 2).c_str(), nullptr, 16));
    }
    return v;
}