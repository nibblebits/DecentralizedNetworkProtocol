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

ClientDomainSocket::ClientDomainSocket()
{
}

ClientDomainSocket::ClientDomainSocket(int client_socket) : DomainSocket()
{
    this->_socket = client_socket;
}

ClientDomainSocket::~ClientDomainSocket()
{
    if (this->_socket != -1)
    {
        close(this->_socket);
    }
}

void ClientDomainSocket::sendPing()
{
    struct DomainPacket packet;
    memset(&packet, 0, sizeof(packet));
    packet.type = DOMAIN_PACKET_TYPE_PING;
    packet.ping_packet.payload = 0xffff;
    sendPacket(&packet);

    // Let's wait for a response
    this->getNextPacket(&packet);

    if (packet.type != DOMAIN_PACKET_TYPE_PING_RESPONSE)
    {
        throw std::logic_error("Unexpected packet response for ping " + std::to_string(packet.type));
    }

    if (packet.ping_packet.payload != packet.ping_packet.payload)
    {
        throw std::logic_error("Server responded with ping response but payload does not much our own.");
    }

}

void ClientDomainSocket::sendPacket(struct DomainPacket *packet)
{
    int rc = send(this->_socket, packet, sizeof(struct DomainPacket), 0);
}

void ClientDomainSocket::connectToServer()
{
    int rc = -1;
    struct sockaddr_un serveraddr;
    this->_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (this->_socket < 0)
    {
        throw std::logic_error("socket() error");
    }

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strcpy(serveraddr.sun_path, DOMAIN_SERVER_PATH);

    rc = connect(this->_socket, (struct sockaddr *)&serveraddr,
                 SUN_LEN(&serveraddr));
    if (rc < 0)
    {
        throw std::logic_error("connect() error, failed to connect to domain server at address " + std::string(DOMAIN_SERVER_PATH));
    }
}

void ClientDomainSocket::process()
{
    // Do nothing.
}

bool ClientDomainSocket::getNextPacket(struct DomainPacket *packet)
{
    // Null this thing
    memset(packet, 0, sizeof(struct DomainPacket));
    int length = -1;
    int rc = -1;

    length = sizeof(struct DomainPacket);
    struct DomainPacket domain_packet;

    rc = setsockopt(this->_socket, SOL_SOCKET, SO_RCVLOWAT,
                    (char *)&length, sizeof(length));
    if (rc < 0)
    {
        throw std::logic_error("Problem with setsockopt");
    }

    rc = recv(this->_socket, &domain_packet, length, 0);
    if (rc < 0)
    {
        // Recv failed then return
        return false;
    }
    memcpy(packet, &domain_packet, sizeof(domain_packet));
    return true;
}

