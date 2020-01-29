#ifndef HELLORESPONDPACKET_H
#define HELLORESPONDPACKET_H

#include "networkpacket.h"
#include <memory>
namespace Dnp
{
class Network;
class HelloRespondPacket : public NetworkPacket
{
public:
    HelloRespondPacket(Network *network);
    virtual ~HelloRespondPacket();
    void setTheirIp(std::string their_ip);

    /**
     * Returns the field "their_ip" if you call this after resurrecting a received packet then this is your IP address.
     * As the original crafter of this packet called setTheirIp and passed in your ip address before sending this packet to you
     */
    std::string getTheirIp();

    virtual void send(std::string ip);
    /**
     * Input is a raw network packet that should have a type of PACKET_TYPE_RESPOND_HELLO
     * Output is a HelloRespondPacket
     **/
    static std::unique_ptr<HelloRespondPacket> resurrect(Network *network, struct Packet *packet);

private:
    std::string their_ip;
};
};

#endif