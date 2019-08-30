#include "serverdomainsocket.h"
#include "clientdomainsocket.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

using namespace Dnp;
ServerDomainSocket::ServerDomainSocket(System* system) : DomainSocket(system)
{

}


ServerDomainSocket::~ServerDomainSocket()
{
    unlink(DOMAIN_SERVER_PATH);

    if (this->_socket != -1)
    {
        close(this->_socket);
    }

}

void ServerDomainSocket::processIncomingDomainPacket(struct DomainPacket* packet, int client_socket)
{

}

void ServerDomainSocket::host()
{
    int rc = -1;
    struct sockaddr_un serveraddr;

    this->_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (this->_socket < 0)
    {
        throw std::logic_error("Socket creation error");
    }

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strcpy(serveraddr.sun_path, DOMAIN_SERVER_PATH);

    rc = bind(this->_socket, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr));
    if (rc < 0)
    {
        throw std::logic_error("Bind error");
    }

    rc = listen(this->_socket, 10);
    if (rc < 0)
    {
        throw std::logic_error("Listen error");
    }

}

void ServerDomainSocket::process()
{
  
}


ServerClientDomainSocket *ServerDomainSocket::acceptSocket()
{
    int client_socket = accept(this->_socket, NULL, NULL);
    if (client_socket < 0)
    {
        throw std::logic_error("Accept error");
    }

    ServerClientDomainSocket* socket = new ServerClientDomainSocket(this->getSystem(), client_socket);

    // Let's spawn a new thread for this socket!
    this->threads.push_back(std::thread(&ServerDomainSocket::socket_thread, this, socket));
    return socket;
}


void ServerDomainSocket::socket_thread(ServerClientDomainSocket* client_socket)
{
    while(1)
    {
        client_socket->process();
    }
}