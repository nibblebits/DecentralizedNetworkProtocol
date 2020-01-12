#ifndef HELLOPACKET_H
#define HELLOPACKET_H

#include "networkpacket.h"
#include <string>
namespace Dnp
{
class Network;
class HelloPacket : public NetworkPacket
{
public:
    HelloPacket(Network *network);
    virtual ~HelloPacket();
    void setTheirIp(std::string ip);
    virtual void send(std::string ip);

private:
    std::string their_ip;
};
}; // namespace Dnp

#endif