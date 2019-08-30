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
class Cell;
class ClientDomainSocket : public DomainSocket
{
public:
    ClientDomainSocket(System* system);
    ClientDomainSocket(System* system, int client_socket);
    virtual ~ClientDomainSocket();
    
    void connectToServer();
    void sendPing();
    void sendCell(Cell* cell);
    virtual void process();
    bool getNextPacket(struct DomainPacket* packet);

protected:
    void sendPacket(struct DomainPacket* packet);
private:
  
};
}; // namespace Dnp
#endif