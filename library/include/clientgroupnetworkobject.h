#ifndef CLIENTGROUPNETWORKOBJECT_H
#define CLIENTGROUPNETWORKOBJECT_H

#include "networkobject.h"
#include "ipv4address.h"

#include <vector>
namespace Dnp
{
class ClientGroupNetworkObject : public NetworkObject
{
public:
    ClientGroupNetworkObject(Network *network);
    virtual ~ClientGroupNetworkObject();
    virtual void send(std::string ip);
    virtual std::unique_ptr<NetworkObject> resurrect(struct NetworkObjectPacket* packet);
private:
    // IP addresses part of this network group
    std::vector<Ipv4Address> addresses;

};
};

#endif