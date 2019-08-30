#include "domainsocket.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

using namespace Dnp;

DomainSocket::DomainSocket(System* system)
{
    this->_socket = -1;
    this->system = system;
}

DomainSocket::DomainSocket(System* system, int _socket)
{
    this->_socket = _socket;
    this->system = system;
}

DomainSocket::~DomainSocket()
{
    if (this->_socket != -1)
    {
        close(this->_socket);
    }
}

System* DomainSocket::getSystem()
{
    return this->system;
}

void DomainSocket::read_blocked(void *data, size_t amount)
{
    int rc = setsockopt(this->_socket, SOL_SOCKET, SO_RCVLOWAT,
                    (char *)&amount, sizeof(amount));
    if (rc < 0)
    {
        throw std::logic_error("Problem with setsockopt");
    }

    rc = recv(this->_socket, data, amount, 0);
    if (rc < 0)
    {
        // Recv failed then return
        throw std::logic_error("read_blocked() failed to recv data");
    }
    
}