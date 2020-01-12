#include "dnpdatagrampacket.h"
#include "network.h"
#include "crypto/rsa.h"
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


void DnpDatagramPacket::send(std::string ip)
{
    if (this->private_key == "" || this->public_key == "")
        throw std::logic_error("You must provide a public and private key");

    struct Packet net_packet = this->network->createPacket(PACKET_TYPE_DATAGRAM);
    memcpy(net_packet.datagram_packet.send_from.address, &this->from, sizeof(this->from));
    memcpy(net_packet.datagram_packet.send_to.address, &this->to, sizeof(this->to));
    memcpy(net_packet.datagram_packet.data.buf, this->data.c_str(), this->data.size());
    Rsa::makeEncryptedHash(data, this->private_key, net_packet.datagram_packet.data.ehash);
    memcpy(net_packet.datagram_packet.sender_public_key, public_key.c_str(), public_key.size());
    this->network->sendPacket(ip, &net_packet);
}