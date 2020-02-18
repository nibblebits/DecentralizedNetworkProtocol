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
    Ipv4Address();
    Ipv4Address(std::string ip);
    Ipv4Address(struct in_addr address);
    Ipv4Address operator=(std::string ip);

    virtual ~Ipv4Address();
    std::string toString();
    bool isBlank();
    struct in_addr raw();

    void setAddress(struct in_addr addr);

    static void getAddressFromString(Ipv4Address& address, std::string ip);
    static Ipv4Address getAddressFromString(std::string ip);

private:
    struct in_addr address;
    bool blank;
};
};

#endif