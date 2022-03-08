#include <sstream>
#include "Global.h"


char Global::pubkey[PUBKEY_LEN * 2 + 3] = {'\0'};
char Global::addr[ADDRESS_LEN * 2 + 3] = {'\0'};
oe_enclave_t *Global::enclave = NULL;

static uint8_t hex2int(char input)
{
    if (input >= '0' && input <= '9')
        return static_cast<uint8_t>(input - '0');
    if (input >= 'A' && input <= 'F')
        return static_cast<uint8_t>(input - 'A' + 10);
    if (input >= 'a' && input <= 'f')
        return static_cast<uint8_t>(input - 'a' + 10);
    return -1;
}
void Global::from_hex(const char *src, char *target)
{
    while (*src && src[1])
    {
        *(target++) = hex2int(*src) * HEX_BASE + hex2int(src[1]);
        src += 2;
    }
}

//std::string Global::to_hex(const unsigned char *data, size_t len)
//{
//    std::stringstream sstream;
//    sstream << std::hex << my_integer;
//    std::string result = sstream.str();
//}
