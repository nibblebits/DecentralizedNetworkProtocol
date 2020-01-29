#ifndef DNPDATAGRAMPACKET_H
#define DNPDATAGRAMPACKET_H

#include "networkpacket.h"
#include "network.h"
#include <string>
#include <memory>

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

    struct DnpAddress getToAddress();
    struct DnpAddress getFromAddress();
    std::string getPublicKey();
    std::string getPrivateKey();
    std::string getData();

    /**
     * Gets the encrypted data hash, note that this data is only valid after you have either sent this packet
     * or after a packet has been resurrected. Otherwise you can assume this data to be garbage and make no sense
     */
    struct DnpEncryptedHash getEncryptedDataHash();
    virtual void send(std::string ip);

   /**
     * Input is a raw network packet that should have a type of PACKET_TYPE_DATAGRAM
     * Output is a DnpDatagramPacket
     **/
    static std::unique_ptr<DnpDatagramPacket> resurrect(Network *network, struct Packet *packet);


private:
    /**
     * Should be used only internally to store encrypted data hash in this object for later retrieval
     */
    void setEncryptedDataHash(struct DnpEncryptedHash ehash);
    struct DnpAddress to;
    struct DnpAddress from;
    std::string data;
    // Encrypted hash of the data
    struct DnpEncryptedHash ehash;

    std::string public_key;
    std::string private_key;

};
}; // namespace Dnp
#endif