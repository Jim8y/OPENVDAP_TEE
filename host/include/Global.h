//
// Created by root on 9/3/19.
//
#include <openenclave/host.h>
#include <iostream>
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

#ifndef GLOBAL_H
#define GLOBAL_H


// used in eth_ecdsa.c
#define SECRETKEY_SEALED_LEN 1024
#define SECKEY_LEN 32
#define PUBKEY_LEN 64
#define ADDRESS_LEN 20


#define ROUND_TO_32(x) ((x + 31) / 32 * 32)

const uint8_t HEX_BASE = 16;
const uint8_t DEC_BASE = 10;

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

namespace openvdap {
    std::vector<uint8_t> from_hex(const char *src);

    void from_hex(const char *src, char *target);

    std::string to_hex(const unsigned char *data, size_t len);
}

template<typename T>
T swap_endian(T u) {
    assert(CHAR_BIT == 8);

    union {
        T u;
        unsigned char u8[sizeof(T)];
    } source, dest;

    source.u = u;

    for (size_t k = 0; k < sizeof(T); k++)
        dest.u8[k] = source.u8[sizeof(T) - k - 1];

    return dest.u;
}

// convert [buf, buf + n] to a T
template<typename T>
T uint_bytes(const unsigned char *buf, size_t n, bool big_endian = true) {
    T ret;
    memcpy(&ret, buf + n - sizeof(T), sizeof(T));
    if (big_endian)
        ret = swap_endian<T>(ret);

    return ret;
}



typedef struct {
    std::string ip;
    int port;
    std::string msg;
} MSG_connect;

class Global {
public:
    static char pubkey[PUBKEY_LEN * 2 + 3];
    static char addr[ADDRESS_LEN * 2 + 3];
    static oe_enclave_t *enclave;
    static void from_hex(const char *src, char *target);
};

#endif //EEVM_GLOBAL_H
