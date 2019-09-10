#include "misc.h"
#include <sstream>

std::string to_hex(const unsigned char* buf, int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++)
    {
        ss << std::hex << (unsigned int) buf[i];
    }

    return ss.str();
}