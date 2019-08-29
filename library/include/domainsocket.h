#ifndef DOMAINSOCKET_H
#define DOMAINSOCKET_H
#include <functional>
#include <thread>
#include <vector>
#include <queue>
namespace Dnp
{
typedef unsigned short DOMAIN_PACKET_TYPE;
enum
{
    DOMAIN_PACKET_TYPE_PING,
    DOMAIN_PACKET_TYPE_PING_RESPONSE
};

struct PingPacket
{
    // These 4 bytes will be returned to the sender as proof of ping
    unsigned int payload;
};

struct DomainPacket
{
    DOMAIN_PACKET_TYPE type;
    union {
        struct PingPacket ping_packet;
    };
};
class DomainSocket
{
public:
    DomainSocket();
    virtual ~DomainSocket();
    virtual void process() = 0;  
protected:

};
}; // namespace Dnp
#endif