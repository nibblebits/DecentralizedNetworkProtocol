#include "testnetworkobject.h"
#include <iostream>
#include <memory.h>
#include "network.h"

using namespace Dnp;
TestNetworkObject::TestNetworkObject(Network* network) : NetworkObject(network, "test")
{
    this->message = "Blank message";
}

TestNetworkObject::~TestNetworkObject()
{

}

void TestNetworkObject::setMessage(std::string message)
{
    this->message = message;
}

std::string TestNetworkObject::getMessage()
{
    return this->message;
}


void TestNetworkObject::send(std::string ip)
{
    network->sendObject(ip, this->message.c_str(), this->message.size(), this); 
}

std::unique_ptr<NetworkObject> TestNetworkObject::resurrect(struct NetworkObjectPacket* packet)
{
    std::unique_ptr<TestNetworkObject> obj = std::make_unique<TestNetworkObject>(this->network);
    obj->setMessage(std::string(packet->obj.data.buf, sizeof(packet->obj.data.buf)));
    return obj;
}