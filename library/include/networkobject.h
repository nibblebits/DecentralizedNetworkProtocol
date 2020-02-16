#ifndef NETWORKOBJECT_H
#define NETWORKOBJECT_H

#include <string>
#include <memory>
#include "network.h"
#include "networkpacket.h"
namespace Dnp
{
class NetworkObject : public NetworkPacket
{
public:
    NetworkObject(Network *network, std::string type);
    virtual ~NetworkObject();

    std::string getType();
    std::string getId();

    /**
     * Generates a unique private/public keypair for this network object.
     * Then hashes the public key with MD5 cipher and makes it this network objects id.
     */
    std::string generateId();
    
    void setPublicKey(std::string public_key);
    void setPrivateKey(std::string private_key);
    void setEncryptedDataHash(std::string encrypted_data_hash);

    std::string getPublicKey();
    std::string getPrivateKey();
    std::string getEncryptedDataHash();
    
    /**
     * Call the static resurrect if you wish to resurrect a network object from a packet
     */
    static std::unique_ptr<NetworkObject> resurrect(Network* network, struct Packet* packet);
    /**
     * Call this method if you wish to resurrect a network object from a packet and you are certain this is the correct network object
     * to resurrect this packet
     */
    virtual std::unique_ptr<NetworkObject> resurrect(struct NetworkObjectPacket* packet) = 0;

    virtual void send(std::string ip) = 0;

protected:
    std::string encrypted_data_hash;
    std::string type;
    std::string id;
    std::string private_key;
    std::string public_key;
};
};
#endif