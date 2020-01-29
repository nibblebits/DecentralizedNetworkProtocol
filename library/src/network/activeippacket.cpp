#include "activeippacket.h"
#include "network.h"
#include "dnpexception.h"
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

std::string ActiveIpPacket::getIp()
{
    return this->ip;
}


void ActiveIpPacket::send(std::string ip)
{
    struct Packet our_packet = network->createPacket(PACKET_TYPE_ACTIVE_IP);
    memset(our_packet.active_ip_packet.ip_address, 0, ip.size());
    memcpy(our_packet.active_ip_packet.ip_address, ip.c_str(), ip.size());
    our_packet.active_ip_packet.ip_address_len = ip.size();
    network->sendPacket(ip, &our_packet);
}



std::unique_ptr<ActiveIpPacket> ActiveIpPacket::resurrect(Network *network, struct Packet *packet)
{
    if (packet->type != PACKET_TYPE_ACTIVE_IP)
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "Provided packet does not have a type of PACKET_TYPE_ACTIVE_IP which is required");

    
    std::unique_ptr<ActiveIpPacket> apacket = network->newPacket<ActiveIpPacket>();
    apacket->setIp(std::string(packet->active_ip_packet.ip_address, packet->active_ip_packet.ip_address_len));
    return apacket;
}