#include "networkpacket.h"
#include "network.h"

using namespace Dnp;
NetworkPacket::NetworkPacket(Network* network)
{
    this->network = network;
}

NetworkPacket::~NetworkPacket()
{

}


void NetworkPacket::broadcast()
{
    for (std::string ip : this->network->getActiveIps())
    {
        send(ip);
    }
}

Network* NetworkPacket::getNetwork()
{
    return this->network;
}

