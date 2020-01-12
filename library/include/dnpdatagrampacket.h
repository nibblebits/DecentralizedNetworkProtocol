#ifndef DNPDATAGRAMPACKET_H
#define DNPDATAGRAMPACKET_H

#include "networkpacket.h"
#include "network.h"
#include <string>

namespace Dnp
{
class Network;
class DnpDatagramPacket : public NetworkPacket
{
public:
    DnpDatagramPacket(Network *network);
    virtual ~DnpDatagramPacket();
    void setFromAddress(std::string ip, unsigned short port);
    void setToAddress(std::string ip, unsigned short port);
    void setData(const char *buf, size_t size);
    void setPublicKey(std::string public_key);
    void setPrivateKey(std::string private_key);

    virtual void send(std::string ip);

private:
    struct DnpAddress to;
    struct DnpAddress from;
    std::string data;
    std::string public_key;
    std::string private_key;

};
}; // namespace Dnp
#endif