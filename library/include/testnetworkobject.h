#ifndef TESTNETWORKOBJECT_H
#define TESTNETWORKOBJECT_H

#include <string>
#include "networkobject.h"
/**
 * 
 * Purely used as a test object for the DNP network
 * Testing purposes only
 */
namespace Dnp
{
class TestNetworkObject : public NetworkObject
{
public:
    TestNetworkObject(Network* network);
    virtual ~TestNetworkObject();
    void setMessage(std::string message);
    std::string getMessage();

    virtual void send(std::string ip);
    virtual std::unique_ptr<NetworkObject> resurrect(struct NetworkObjectPacket* packet);
private:
    std::string message;

  
};
};
#endif