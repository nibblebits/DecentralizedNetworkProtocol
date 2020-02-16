#ifndef IPV4ADDRESS_H
#define IPV4ADDRESS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>

namespace Dnp
{
class Ipv4Address
{
public:
    Ipv4Address(struct in_addr address);
    virtual ~Ipv4Address();
    std::string toString();
    struct in_addr raw();

private:
    struct in_addr address;
};
};

#endif