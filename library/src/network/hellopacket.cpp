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

void HelloPacket::setTheirIp(std::string ip)
{
    if (ip.size() == 0 || ip.size() > 16)
    {
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "The IP set is out of bounds or illegal: size = " + std::to_string(their_ip.size()));
    }

    this->their_ip = ip;
}

std::string HelloPacket::getTheirIp()
{
    return this->their_ip;
}

std::unique_ptr<HelloPacket> HelloPacket::resurrect(Network *network, struct Packet *packet)
{
    if (packet->type != PACKET_TYPE_INITIAL_HELLO)
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "Provided packet does not have a type of PACKET_TYPE_INITIAL_HELLO which is required");

    if (packet->hello_packet.your_ip_len == 0)
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "Provided ip address has a length of zero, is this a corrupted packet: " + std::to_string(packet->hello_packet.your_ip_len));

    std::unique_ptr<HelloPacket> hpacket = network->newPacket<HelloPacket>();
    hpacket->setTheirIp(std::string(packet->hello_packet.your_ip, packet->hello_packet.your_ip_len));
    return hpacket;
}

void HelloPacket::send(std::string ip)
{
    if (their_ip.size() == 0)
    {
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "You never provided the their_ip field please call setTheirIp");
    }

    // Send the hello packet
    Packet packet_to_send = network->createPacket(PACKET_TYPE_INITIAL_HELLO);
    memcpy(packet_to_send.hello_packet.your_ip, their_ip.c_str(), their_ip.size());
    packet_to_send.hello_packet.your_ip_len = their_ip.size();
    network->sendPacket(ip, &packet_to_send);
}