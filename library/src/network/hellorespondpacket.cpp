#include "hellorespondpacket.h"
#include "network.h"
#include "dnpexception.h"
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

std::string HelloRespondPacket::getTheirIp()
{
    return this->their_ip;
}

void HelloRespondPacket::send(std::string ip)
{
    Packet packet_to_send = network->createPacket(PACKET_TYPE_RESPOND_HELLO);
    memcpy(packet_to_send.hello_packet.your_ip, their_ip.c_str(), their_ip.size());
    packet_to_send.hello_packet.your_ip_len = their_ip.size();

    network->sendPacket(their_ip, &packet_to_send);
}

std::unique_ptr<HelloRespondPacket> HelloRespondPacket::resurrect(Network *network, struct Packet *packet)
{
    if (packet->type != PACKET_TYPE_RESPOND_HELLO)
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "Provided packet does not have a type of PACKET_TYPE_RESPOND_HELLO which is required");

    if (packet->hello_packet.your_ip_len == 0)
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "Provided ip address has a length of zero, is this a corrupted packet: " + std::to_string(packet->hello_packet.your_ip_len));

    std::unique_ptr<HelloRespondPacket> hpacket = network->newPacket<HelloRespondPacket>();
    hpacket->setTheirIp(std::string(packet->hello_packet.your_ip, packet->hello_packet.your_ip_len));
    return hpacket;
}