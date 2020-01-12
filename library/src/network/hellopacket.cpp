#include "hellopacket.h"
#include "network.h"
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
    this->their_ip = ip;
}


void HelloPacket::send(std::string ip)
{
    // Send the hello packet
    Packet packet_to_send = network->createPacket(PACKET_TYPE_INITIAL_HELLO);
    memcpy(packet_to_send.hello_packet.your_ip, their_ip.c_str(), their_ip.size());
    network->sendPacket(ip, &packet_to_send);
}