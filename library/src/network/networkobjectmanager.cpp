#include "networkobjectmanager.h"
#include <algorithm>

using namespace Dnp;

NetworkObjectManager::NetworkObjectManager()
{

}

NetworkObjectManager::~NetworkObjectManager()
{

}


void NetworkObjectManager::registerNetworkObject(std::unique_ptr<NetworkObject> obj)
{
    std::string type = obj->getType();
    this->obj_map[type] = std::move(obj);
}

NetworkObject* NetworkObjectManager::findObjectWithType(std::string name)
{
    if (this->obj_map.find(name) == this->obj_map.end())
        return nullptr;


    return this->obj_map.at(name).get();
}