#include "hellopacket.h"
#include "network.h"
#include "dnpexception.h"
#include <memory.h>

using namespace Dnp;

HelloPacket::HelloPacket(Network *network) : NetworkPacket(network)
{
}

HelloPacket::~HelloPacket()
{
}

void HelloPacket::setTheirIp(Ipv4Address ip)
{
    if (ip.isBlank())
    {
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "The IP set is blank!");
    }

    this->their_ip = ip;
}

Ipv4Address HelloPacket::getTheirIp()
{
    return this->their_ip;
}

std::unique_ptr<HelloPacket> HelloPacket::resurrect(Network *network, struct Packet *packet)
{
    if (packet->type != PACKET_TYPE_INITIAL_HELLO)
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "Provided packet does not have a type of PACKET_TYPE_INITIAL_HELLO which is required");

    struct Ipv4Address ip(packet->hello_packet.ip);
    std::unique_ptr<HelloPacket> hpacket = network->newPacket<HelloPacket>();
    hpacket->setTheirIp(ip);
    return hpacket;
}

void HelloPacket::send(std::string ip)
{
    if (their_ip.isBlank())
    {
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "You never provided the their_ip field please call setTheirIp");
    }

    // Send the hello packet
    Packet packet_to_send = network->createPacket(PACKET_TYPE_INITIAL_HELLO);
    packet_to_send.hello_packet.ip = their_ip.raw();
    network->sendPacket(ip, &packet_to_send);
}