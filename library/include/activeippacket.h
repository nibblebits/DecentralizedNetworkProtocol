#ifndef ACTIVEIPPACKET_H
#define ACTIVEIPPACKET_H

#include "networkpacket.h"
#include <string>
#include <memory>
namespace Dnp
{
class Network;

class ActiveIpPacket : public NetworkPacket
{
public:
    ActiveIpPacket(Network *network);
    virtual ~ActiveIpPacket();
    void setIp(std::string ip);

    /**
     * Extracts the active IP from this packet. That we should be aware of
     */
    std::string getIp();
    virtual void send(std::string ip);

    /**
     * Input is a raw network packet that should have a type of PACKET_TYPE_ACTIVE_IP
     * Output is a ActiveIpPacket
     **/
    static std::unique_ptr<ActiveIpPacket> resurrect(Network *network, struct Packet *packet);

private:
    std::string ip;
};
}; // namespace Dnp

#endif