#ifndef HELLOPACKET_H
#define HELLOPACKET_H

#include "networkpacket.h"
#include "network.h"
#include "ipv4address.h"

#include <string>
#include <memory>
namespace Dnp
{
class HelloPacket : public NetworkPacket
{
public:
    HelloPacket(Network *network);
    virtual ~HelloPacket();
    /**
     * Used to set the ip field so that when we sent this hello packet
     * the receiver will know his ip address
     */
    void setTheirIp(Ipv4Address ip);
    /**
     * Returns the field "their_ip" if you call this after resurrecting a received packet then this is your IP address.
     * As the original crafter of this packet called setTheirIp and passed in your ip address before sending this packet to you
     */
    Ipv4Address getTheirIp();

    /**
     * Input is a raw network packet that should have a type of PACKET_TYPE_INITIAL_HELLO
     * Output is a HelloPacket
     **/
    static std::unique_ptr<HelloPacket> resurrect(Network* network, struct Packet* packet);
    virtual void send(std::string ip);

private:
    Ipv4Address their_ip;
};
}; // namespace Dnp

#endif