#ifndef CLIENTDOMAINSOCKET_H
#define CLIENTDOMAINSOCKET_H
#include <functional>
#include <thread>
#include <mutex>
#include <vector>
#include <queue>
#include "domainsocket.h"
namespace Dnp
{

class ClientDomainSocket : public DomainSocket
{
public:
    ClientDomainSocket();
    ClientDomainSocket(int client_socket);
    virtual ~ClientDomainSocket();
    
    void connectToServer();
    void sendPing();
    virtual void process();
    bool getNextPacket(struct DomainPacket* packet);

protected:
    void sendPacket(struct DomainPacket* packet);
private:
    int _socket;
  
};
}; // namespace Dnp
#endif