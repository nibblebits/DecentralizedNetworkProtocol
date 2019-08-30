#include "serverclientdomainsocket.h"
#include "config.h"
#include "cell.h"
#include "system.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <iostream>

using namespace Dnp;
ServerClientDomainSocket::ServerClientDomainSocket(System* system, int client_socket) : DomainSocket(system, client_socket)
{
}

ServerClientDomainSocket::~ServerClientDomainSocket()
{
    
}

void ServerClientDomainSocket::connectToServer()
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
        throw std::logic_error("rc error");
    }
}

void ServerClientDomainSocket::process()
{
    while(1)
    {
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
            // Recv failed then break
            break;
        }

        // Great we have the domain packet let's process this incoming packet
        this->processIncomingDomainPacket(&domain_packet);
    }
}

void ServerClientDomainSocket::sendPacket(struct DomainPacket* packet)
{
    int rc = send(this->_socket, packet, sizeof(struct DomainPacket), 0);
}

void ServerClientDomainSocket::processPingPacket(struct DomainPacket* packet)
{
    // Send the packet back
    packet->type = DOMAIN_PACKET_TYPE_PING_RESPONSE;
    this->sendPacket(packet);
}

void ServerClientDomainSocket::processCellPacket(struct DomainPacket* packet)
{
    struct DomainCellPublishPacket* publish_packet = &packet->publish_packet;
    // We need to allocate some memory for this packet payload
//  std::unique_ptr<unsigned char[]> payload(new unsigned char[publish_packet->cell_data_size]());

    char* payload = new char[publish_packet->cell_data_size];
    // We need to read the data of cell_data_size as this is the cell packet payload
    read_blocked(payload, publish_packet->cell_data_size);

    // Reconstruct the cell
    Cell cell(publish_packet->cell_id, this->getSystem());
    cell.setData(payload, publish_packet->cell_data_size);

    struct DomainPacket res_packet;
    res_packet.type = DOMAIN_PACKET_TYPE_CELL_PUBLISH_RESPONSE;
    res_packet.publish_response_packet.cell_id = cell.getId();
    try
    {
        // Now we have everything we need let's add this cell to the network for later processing
        this->getSystem()->addCellForProcessing(cell);

        // This was succesful the cell has been added for processing
        res_packet.publish_response_packet.state = DOMAIN_PUBLISH_PACKET_STATE_OK_PROCESSING;
    }
    catch(std::exception& ex)
    {
        res_packet.publish_response_packet.state = DOMAIN_PUBLISH_PACKET_STATE_PUBLISH_FAILED;
    }

    // Let's send our response
    this->sendPacket(&res_packet);
    
}

void ServerClientDomainSocket::processIncomingDomainPacket(struct DomainPacket* packet)
{
    // Ok we have an incoming packet let's process it
    switch(packet->type)
    {
        case DOMAIN_PACKET_TYPE_PING:
            this->processPingPacket(packet);
        break;

        case DOMAIN_PACKET_TYPE_CELL_PUBLISH:
            this->processCellPacket(packet);
        break;
    }
}