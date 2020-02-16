#include "networkobject.h"
#include "networkobjectmanager.h"
#include "dnpexception.h"
#include "crypto/rsa.h"
#include "misc.h"
#include <string.h>

using namespace Dnp;
NetworkObject::NetworkObject(Network *network, std::string type) : NetworkPacket(network)
{
    this->id = "";
    this->type = type;
    this->private_key = "";
    this->public_key = "";
}

NetworkObject::~NetworkObject()
{
}

std::string NetworkObject::generateId()
{
    struct rsa_keypair keypair = Rsa::generateKeypair();
    this->public_key = keypair.pub_key;
    this->private_key = keypair.private_key;
    this->id = keypair.pub_key_md5_hash;
    return this->id;
}

std::unique_ptr<NetworkObject> NetworkObject::resurrect(Network *network, struct Packet *packet)
{
    if (packet->type != PACKET_TYPE_OBJECT_PUBLISH)
    {
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "The wrong network packet was provided for ressurection");
    }

    struct NetworkObjectPacket *npacket = &packet->network_object_packet;
    if (npacket->obj.type_len >= sizeof(npacket->obj.type))
        throw DnpException(DNP_EXCEPTION_UNKNOWN, "Packet is dangerous has size larger than buffer allows, processing will not continue");
    
    std::string type = std::string(npacket->obj.type, npacket->obj.type_len);
    NetworkObjectManager* obj_manager = network->getObjectManager();
    NetworkObject* obj = obj_manager->findObjectWithType(type);
    if (!obj)
    {
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "Your instance of DNP is not aware of any objects with the type: " + type + " we can't really do anything else");
    }

    DnpEncryptedHash* hash = &npacket->obj.data.ehash;
    if (hash->size > sizeof(hash->hash))
        throw DnpException(DNP_EXCEPTION_OUT_OF_BOUNDS, "Packet is forged, attempting to overflow buffer!!!");

    std::string data_str = std::string(npacket->obj.data.buf, sizeof(npacket->obj.data.buf));
    std::string public_key = std::string(npacket->obj.public_key, strnlen(npacket->obj.public_key, sizeof(npacket->obj.public_key)));
    std::string encrypted_hash = std::string(npacket->obj.data.ehash.hash, npacket->obj.data.ehash.size);
    std::string decrypted_hash = "";

    Rsa::decrypt_public(public_key, encrypted_hash, decrypted_hash);
    std::string data_hash = md5_hex(data_str);
    if (decrypted_hash != data_hash)
    {
        throw DnpException(DNP_EXCEPTION_SIGNATURE_FAILURE, "This packet has failed the signing process, its probably forged");
    }
    return obj->resurrect(npacket);
}

void NetworkObject::setPublicKey(std::string public_key)
{
    this->public_key = public_key;
}

void NetworkObject::setPrivateKey(std::string private_key)
{
    this->private_key = private_key;
}

void NetworkObject::setEncryptedDataHash(std::string encrypted_data_hash)
{
    this->encrypted_data_hash = encrypted_data_hash;
}

std::string NetworkObject::getPublicKey()
{
    return this->public_key;
}
std::string NetworkObject::getPrivateKey()
{
    return this->private_key;
}

std::string NetworkObject::getEncryptedDataHash()
{
    return this->encrypted_data_hash;
}

std::string NetworkObject::getType()
{
    return this->type;
}

std::string NetworkObject::getId()
{
    return this->id;
}
