#include "ipv4address.h"
#include <memory.h>
#include <stdlib.h>

using namespace Dnp;
Ipv4Address::Ipv4Address(struct in_addr address)
{
    this->address = address;
}

Ipv4Address::~Ipv4Address()
{

}

std::string Ipv4Address::toString()
{
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(this->address), ip, INET_ADDRSTRLEN);
    return std::string(ip, strnlen(ip, INET_ADDRSTRLEN));
}

struct in_addr Ipv4Address::raw()
{
    return this->address;
}

