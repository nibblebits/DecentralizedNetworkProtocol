#include "hellorespondpacket.h"
#include "network.h"
#include <memory.h>


using namespace Dnp;
HelloRespondPacket::HelloRespondPacket(Network *network) : NetworkPacket(network)
{
}

HelloRespondPacket::~HelloRespondPacket()
{
}

void HelloRespondPacket::setTheirIp(std::string their_ip)
{
    this->their_ip = their_ip;
}

void HelloRespondPacket::send(std::string ip)
{
    Packet packet_to_send = network->createPacket(PACKET_TYPE_RESPOND_HELLO);
    memcpy(packet_to_send.hello_packet.your_ip, their_ip.c_str(), their_ip.size());
    network->sendPacket(their_ip, &packet_to_send);
}