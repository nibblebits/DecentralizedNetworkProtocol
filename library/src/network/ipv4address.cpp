#include "ipv4address.h"
#include <memory.h>
#include <stdlib.h>
#include <stdexcept>

using namespace Dnp;
Ipv4Address::Ipv4Address()
{
    this->blank = true;
}

Ipv4Address::Ipv4Address(struct in_addr address)
{
    this->address = address;
    this->blank = false;
}

Ipv4Address::Ipv4Address(std::string ip)
{
    Ipv4Address::getAddressFromString(*this, ip);
}

Ipv4Address Ipv4Address::operator=(std::string ip)
{
    return Ipv4Address(ip);
}

Ipv4Address::~Ipv4Address()
{
}

std::string Ipv4Address::toString()
{
    if (this->blank)
        return "not_set";

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(this->address), ip, INET_ADDRSTRLEN);
    return std::string(ip, strnlen(ip, INET_ADDRSTRLEN));
}

bool Ipv4Address::isBlank()
{
    return this->blank;
}

struct in_addr Ipv4Address::raw()
{
    return this->address;
}

void Ipv4Address::setAddress(struct in_addr addr)
{
    this->address = addr;
    this->blank = false;
}

void Ipv4Address::getAddressFromString(Ipv4Address &address, std::string ip)
{
    struct in_addr addr;
    if (!inet_pton(AF_INET, ip.c_str(), &addr))
    {
        throw std::logic_error("Issue getting address from string");
    }

    address.setAddress(addr);
}

Ipv4Address Ipv4Address::getAddressFromString(std::string ip)
{
    struct Ipv4Address address;
    getAddressFromString(address, ip);
    return address;
}
