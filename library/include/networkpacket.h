#ifndef NETWORKPACKET_H
#define NETWORKPACKET_H

#include <string>
namespace Dnp
{
class Network;
class NetworkPacket
{
public:
    NetworkPacket(Network *network);
    virtual ~NetworkPacket();
    virtual void send(std::string ip) = 0;
    virtual void broadcast();
    
    Network* getNetwork();

protected:
    Network* network;
};
}; // namespace Dnp

#endif