#ifndef PINGPACKET_H
#define PINGPACKET_H

#include "networkpacket.h"
#include <string>
#include <memory>


namespace Dnp
{
class Network;
class PingPacket : public NetworkPacket
{
public:
    PingPacket(Network *network);
    virtual ~PingPacket();

    virtual void send(std::string ip);

    /**
     * Input is a raw network packet that should have a type of PACKET_TYPE_PING
     * Output is a PingPacket
     **/
    static std::unique_ptr<PingPacket> resurrect(Network *network, struct Packet *packet);
};
};

#endif