#include "pingpacket.h"
#include "network.h"
#include "dnpexception.h"
using namespace Dnp;

PingPacket::PingPacket(Network *network) : NetworkPacket(network)
{
}

PingPacket::~PingPacket()
{
}

void PingPacket::send(std::string ip)
{
    Packet packet = this->network->createPacket(PACKET_TYPE_PING);
    this->network->sendPacket(ip, &packet);
}

std::unique_ptr<PingPacket> PingPacket::resurrect(Network *network, struct Packet *packet)
{
    if (packet->type != PACKET_TYPE_PING)
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "Provided packet does not have a type of PACKET_TYPE_PING which is required");

    std::unique_ptr<PingPacket> ping_packet = network->newPacket<PingPacket>();
    return ping_packet;
}