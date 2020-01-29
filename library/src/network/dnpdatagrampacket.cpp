#include "dnpdatagrampacket.h"
#include "network.h"
#include "crypto/rsa.h"
#include "dnpexception.h"
#include <memory.h>

using namespace Dnp;

DnpDatagramPacket::DnpDatagramPacket(Network *network) : NetworkPacket(network)
{
    memset(&this->to, 0, sizeof(this->to));
    memset(&this->from, 0, sizeof(this->from));
    this->data = "";
    this->private_key = "";
    this->public_key = "";
}
DnpDatagramPacket::~DnpDatagramPacket()
{
}

void DnpDatagramPacket::setFromAddress(std::string ip, unsigned short port)
{
    if (ip.size() > sizeof(from.address))
        throw std::logic_error("Out of bounds");

    memcpy(this->from.address, ip.c_str(), ip.size());
    this->from.port = port;
}
void DnpDatagramPacket::setToAddress(std::string ip, unsigned short port)
{
    if (ip.size() > sizeof(to.address))
        throw std::logic_error("Out of bounds");

    memcpy(this->to.address, ip.c_str(), ip.size());
    this->to.port = port;
}

void DnpDatagramPacket::setData(const char *buf, size_t size)
{
    this->data = std::string(buf, size);
}

void DnpDatagramPacket::setPublicKey(std::string public_key)
{
    this->public_key = public_key;
}

void DnpDatagramPacket::setPrivateKey(std::string private_key)
{
    this->private_key = private_key;
}

struct DnpAddress DnpDatagramPacket::getToAddress()
{
    return this->to;
}

struct DnpAddress DnpDatagramPacket::getFromAddress()
{
    return this->from;
}

std::string DnpDatagramPacket::getPublicKey()
{
    return this->public_key;
}

std::string DnpDatagramPacket::getPrivateKey()
{
    return this->private_key;
}

std::string DnpDatagramPacket::getData()
{
    return this->data;
}

struct DnpEncryptedHash DnpDatagramPacket::getEncryptedDataHash()
{
    return this->ehash;
}

void DnpDatagramPacket::send(std::string ip)
{
    if (this->private_key == "" || this->public_key == "")
        throw std::logic_error("You must provide a public and private key");

    struct Packet net_packet = this->network->createPacket(PACKET_TYPE_DATAGRAM);
    memcpy(net_packet.datagram_packet.send_from.address, &this->from, sizeof(this->from));
    memcpy(net_packet.datagram_packet.send_to.address, &this->to, sizeof(this->to));
    memcpy(net_packet.datagram_packet.data.buf, this->data.c_str(), this->data.size());

    // Create a hash of the data but also store it in this object so it can be retrieved later on
    Rsa::makeEncryptedHash(data, this->private_key, this->ehash);
    memcpy(&net_packet.datagram_packet.data.ehash, &this->ehash, sizeof(this->ehash));

    memcpy(net_packet.datagram_packet.sender_public_key, public_key.c_str(), public_key.size());
    this->network->sendPacket(ip, &net_packet);
}

std::unique_ptr<DnpDatagramPacket> DnpDatagramPacket::resurrect(Network *network, struct Packet *packet)
{
    if (packet->type != PACKET_TYPE_DATAGRAM)
    {
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "You have passed in an invalid packet, expecting to ressurect a type of PACKET_TYPE_DATAGRAM");
    }

    struct _DnpDatagramPacket *rpacket = &packet->datagram_packet;
    std::unique_ptr<DnpDatagramPacket> ddpacket = network->newPacket<DnpDatagramPacket>();
    ddpacket->setFromAddress(std::string(rpacket->send_from.address, sizeof(rpacket->send_from.address)),
                             rpacket->send_from.port);
    ddpacket->setToAddress(std::string(rpacket->send_to.address, sizeof(rpacket->send_to.address)), rpacket->send_to.port);
    ddpacket->setPublicKey(std::string(rpacket->sender_public_key, sizeof(rpacket->sender_public_key)));
    ddpacket->setData(packet->datagram_packet.data.buf, sizeof(packet->datagram_packet.data.buf));
    ddpacket->setEncryptedDataHash(packet->datagram_packet.data.ehash);
    return ddpacket;
}