#include "activeippacket.h"
#include "network.h"
#include <memory.h>

using namespace Dnp;

ActiveIpPacket::ActiveIpPacket(Network *network) : NetworkPacket(network)
{
}

ActiveIpPacket::~ActiveIpPacket()
{
}

void ActiveIpPacket::setIp(std::string ip)
{
    this->ip = ip;
}

void ActiveIpPacket::send(std::string ip)
{
    struct Packet our_packet = network->createPacket(PACKET_TYPE_ACTIVE_IP);
    memset(our_packet.active_ip_packet.ip_address, 0, ip.size());
    memcpy(our_packet.active_ip_packet.ip_address, ip.c_str(), ip.size());
    network->sendPacket(ip, &our_packet);
}