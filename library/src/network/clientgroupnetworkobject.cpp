#include "clientgroupnetworkobject.h"
using namespace Dnp;
ClientGroupNetworkObject::ClientGroupNetworkObject(Network* network) : NetworkObject(network, "group")
{
    
}

ClientGroupNetworkObject::~ClientGroupNetworkObject()
{

}

void ClientGroupNetworkObject::send(std::string ip)
{
    //Let's send the network group
    #warning "Not implemented"

}

std::unique_ptr<NetworkObject> ClientGroupNetworkObject::resurrect(NetworkObjectPacket* packet)
{
    // Let's ressurect this packet
    #warning "not implemented"
    return std::make_unique<ClientGroupNetworkObject>(this->network);
}