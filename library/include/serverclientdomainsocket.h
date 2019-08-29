#ifndef SERVERCLIENTDOMAINSOCKET_H
#define SERVERCLIENTDOMAINSOCKET_H
#include <functional>
#include <thread>
#include <mutex>
#include <vector>
#include <queue>
#include "domainsocket.h"
namespace Dnp
{

class ServerClientDomainSocket : public DomainSocket
{
public:
    ServerClientDomainSocket(int client_socket);
    virtual ~ServerClientDomainSocket();
    
    void connectToServer();
    virtual void process();
protected:
    void sendPacket(struct DomainPacket* packet);
    void processPingPacket(struct DomainPacket* packet);
    virtual void processIncomingDomainPacket(struct DomainPacket* packet);
private:
    int _socket;
  
};
}; // namespace Dnp
#endif