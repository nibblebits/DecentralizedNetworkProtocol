#include "clientdomainsocket.h"
#include "config.h"
#include "cell.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

using namespace Dnp;

ClientDomainSocket::ClientDomainSocket(System* system) : DomainSocket(system)
{
}

ClientDomainSocket::ClientDomainSocket(System* system, int client_socket) : DomainSocket(system, client_socket)
{
}

ClientDomainSocket::~ClientDomainSocket()
{
  
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

    assert_packet_type(&packet, DOMAIN_PACKET_TYPE_PING_RESPONSE);

    if (packet.ping_packet.payload != packet.ping_packet.payload)
    {
        throw std::logic_error("Server responded with ping response but payload does not much our own.");
    }

}

void ClientDomainSocket::sendPacket(struct DomainPacket *packet)
{
    int rc = send(this->_socket, packet, sizeof(struct DomainPacket), 0);
    if (rc < 0)
    {
        throw std::logic_error("Failed to send packet rc= " + std::to_string(rc));
    }
}

void ClientDomainSocket::sendCell(Cell* cell)
{
    struct DomainPacket packet;
    packet.type = DOMAIN_PACKET_TYPE_CELL_PUBLISH;
    packet.publish_packet.cell_id = cell->getId();
    packet.publish_packet.cell_data_size = cell->getDataSize();
    this->sendPacket(&packet);

    // Now we sent the packet the server expects the payload
    int rc = send(this->_socket, cell->getData(), cell->getDataSize(), 0);
    if (rc < 0)
    {
        throw std::logic_error("Failed to send cell payload rc= " + std::to_string(rc));
    }

    // Ok lets get a response
    struct DomainPacket res_packet;
    this->getNextPacket(&res_packet);

    // Ok let's check this was the correct response
    assert_packet_type(&res_packet, DOMAIN_PACKET_TYPE_CELL_PUBLISH_RESPONSE);

    // Its a cell publish response let's ensure that the cell was published correctly
    if (res_packet.publish_response_packet.state != DOMAIN_PUBLISH_PACKET_STATE_OK_PROCESSING)
    {
        throw std::logic_error("sendCell() failed. DNP Server responded with publish packet state " + std::to_string(res_packet.publish_response_packet.state));
    }
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

void ClientDomainSocket::getNextPacket(struct DomainPacket *packet)
{
    // Null this thing
    memset(packet, 0, sizeof(struct DomainPacket));
    int length = -1;
    int rc = -1;

    length = sizeof(struct DomainPacket);
    read_blocked(packet, sizeof(struct DomainPacket));
 
    memcpy(packet, packet, sizeof(struct DomainPacket));
}

