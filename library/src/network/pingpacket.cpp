#include "pingpacket.h"
#include "network.h"
using namespace Dnp;

PingPacket::PingPacket(Network* network) : NetworkPacket(network)
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
