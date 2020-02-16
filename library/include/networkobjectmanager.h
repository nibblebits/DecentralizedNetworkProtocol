#ifndef NETWORKOBJECTMANAGER_H
#define NETWORKOBJECTMANAGER_H

#include <string>
#include <map>
#include <memory>
#include "networkobject.h"
namespace Dnp
{
class NetworkObjectManager
{
public:
    NetworkObjectManager();
    virtual ~NetworkObjectManager();

    void registerNetworkObject(std::unique_ptr<NetworkObject> obj);
    NetworkObject* findObjectWithType(std::string name);

private:
    std::map<std::string, std::unique_ptr<NetworkObject>> obj_map;
  
};
};
#endif