#ifndef ACTIVEIPPACKET_H
#define ACTIVEIPPACKET_H

#include "networkpacket.h"
#include <string>
namespace Dnp
{
class Network;
class ActiveIpPacket : public NetworkPacket
{
public:
    ActiveIpPacket(Network *network);
    virtual ~ActiveIpPacket();
    void setIp(std::string ip);
    virtual void send(std::string ip);

private:
    std::string ip;
};
}; // namespace Dnp

#endif