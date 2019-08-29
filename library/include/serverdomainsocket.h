#ifndef SERVERDOMAINSOCKET_H
#define SERVERDOMAINSOCKET_H
#include <functional>
#include <thread>
#include <vector>
#include <queue>
#include "domainsocket.h"
#include "serverclientdomainsocket.h"
namespace Dnp
{

class ServerDomainSocket : public DomainSocket
{
public:
    ServerDomainSocket();
    virtual ~ServerDomainSocket();
    
    void host();
    ServerClientDomainSocket* acceptSocket();
    virtual void process();
    

protected:
    virtual void processIncomingDomainPacket(struct DomainPacket* packet, int client_socket);
private:
    void socket_thread(ServerClientDomainSocket* client_socket);
    // Vector of threads relating to domain sockets
    std::vector<std::thread> threads;
    int _socket;

};
}; // namespace Dnp
#endif