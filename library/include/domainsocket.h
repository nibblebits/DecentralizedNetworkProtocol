#ifndef DOMAINSOCKET_H
#define DOMAINSOCKET_H
#include <functional>
#include <thread>
#include <vector>
#include <queue>
#include "types.h"
namespace Dnp
{
class System;
typedef unsigned short DOMAIN_PACKET_TYPE;
enum
{
    DOMAIN_PACKET_TYPE_PING,
    DOMAIN_PACKET_TYPE_PING_RESPONSE,
    DOMAIN_PACKET_TYPE_CELL_PUBLISH,
    DOMAIN_PACKET_TYPE_CELL_PUBLISH_RESPONSE
};

struct DomainPingPacket
{
    // These 4 bytes will be returned to the sender as proof of ping
    unsigned int payload;
};


struct DomainCellPublishPacket
{
    CELL_ID cell_id;
    unsigned long cell_data_size;
    // Cell data follows after receving this packet, read cell_data_size x bytes
};

struct DomainPacket
{
    DOMAIN_PACKET_TYPE type;
    union {
        struct DomainPingPacket ping_packet;
        struct DomainCellPublishPacket publish_packet;
    };
};

class DomainSocket
{
public:
    DomainSocket(System* system);
    DomainSocket(System* system, int _socket);
    virtual ~DomainSocket();
    System* getSystem();
    void read_blocked(void* data, size_t amount);
    virtual void process() = 0;  
protected:
    int _socket;
    System* system;


};
}; // namespace Dnp
#endif