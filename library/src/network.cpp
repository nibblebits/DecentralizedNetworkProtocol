/*
Dnp Decentralized Network Protocol

Copyright (C) 2019  Daniel McCarthy
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "network.h"
#include "config.h"
#include "dnpfile.h"
#include "dnpexception.h"
#include "dnpmodshared.h"
#include "misc.h"
#include "crypto/rsa.h"
#include <iostream>

#include <sstream>
#include <string>
#include <fstream>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

using namespace Dnp;
Network::Network()
{
}
Network::Network(System *system)
{
    this->is_binded = false;
    this->our_ip = "unknown ip";
    this->dnp_file = system->getDnpFile();
    this->system = system;
}

Network::~Network()
{
    if (this->network_recv_thread.joinable())
        this->network_recv_thread.join();

    if (this->network_general_thread.joinable())
        this->network_general_thread.join();
}

void Network::makeEncryptedHash(struct DnpEncryptedHash* out, const char* hash, DATA_HASH_SIZE size)
{
    if (size > sizeof(out->hash))
        throw std::logic_error("Hash exceeds maximum possible size for transit");
    memcpy(out, hash, size);
    out->size = size;
}

void Network::network_recv_thread_operation(Network *network)
{
    network->network_recv_thread_run();
}

void Network::network_general_thread_operation(Network *network)
{
    network->network_general_thread_run();
}

void Network::network_recv_thread_run()
{

    std::unique_lock<std::mutex> lk(this->thread_lock);
    binded_cv.wait(lk, [&] { return is_binded; });
    struct sockaddr_in client_address;
    socklen_t len = sizeof(struct sockaddr_in);
    int n;
    char buffer[MAX_PACKET_SIZE];
    while (1)
    {
        n = recvfrom(our_socket, (char *)buffer, MAX_PACKET_SIZE,
                     MSG_WAITALL, (struct sockaddr *)&client_address,
                     &len);
        handleIncomingPacket(client_address, (Packet *)buffer);
    }
}

void Network::ping()
{
    Packet packet;
    packet.type = PACKET_TYPE_PING;
    broadcast(&packet);
}

void Network::network_general_thread_run()
{

    while (1)
    {
        {
            // Scan for IP's that are now online
            scan();
        }

        // Ping the network to keep all ports alive
        ping();
        sleep(5);
    }
}

void Network::begin()
{
    // Load the IP addresses
    std::string ip_str;
    unsigned long current_index = 0;
    while (this->dnp_file->getNextIp(ip_str, &current_index))
    {
        std::cout << "Known IP: " << ip_str << std::endl;
        this->known_ips.push_back(ip_str);
    }

    if (this->known_ips.empty())
    {
        throw std::logic_error("The system is not aware of any ip addresses to try, modify DNP file to add one");
    }

    this->network_recv_thread = std::thread(&Network::network_recv_thread_operation, this);
    this->network_general_thread = std::thread(&Network::network_general_thread_operation, this);
}

int Network::get_valid_socket(struct sockaddr_in *servaddr)
{

    int s = -1;
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        return s;
    }
    servaddr->sin_family = AF_INET; // IPv4
    servaddr->sin_addr.s_addr = INADDR_ANY;
    bool bind_success = false;
    for (int i = PORT_RANGE_START; i < PORT_RANGE_END; i++)
    {
        servaddr->sin_port = htons(i);
        std::cout << "Attempting port: " + std::to_string(i) << std::endl;
        if (bind(s, (const sockaddr *)servaddr,
                 sizeof(struct sockaddr_in)) >= 0)
        {
            bind_success = true;
            break;
        }
    }

    if (!bind_success)
    {
        std::cout << "bind problem" << std::endl;
        return -1;
    }

    return s;
}

void Network::scan()
{
    for (std::string ip : this->known_ips)
    {
        if (!isActiveIp(ip))
        {
            struct Packet packet;
            memset(&packet, 0, sizeof(struct Packet));
            packet.type = PACKET_TYPE_INITIAL_HELLO;
            memcpy(packet.hello_packet.your_ip, ip.c_str(), ip.size());
            sendPacket(ip, &packet);
            std::cout << "Sent hello packet: " << ip << std::endl;
        }
    }
}

void Network::bindMyself()
{

    // Creating socket file descriptor
    if ((our_socket = get_valid_socket(&this->our_address)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    {
        std::lock_guard<std::mutex> lk(this->thread_lock);
        is_binded = true;
    }
    binded_cv.notify_all();
}

void Network::sendPacket(std::string ip, struct Packet *packet)
{
    struct sockaddr_in server_address;
    for (int i = PORT_RANGE_START; i < PORT_RANGE_END; i++)
    {
        memset(&server_address, 0, sizeof(server_address));
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(i);
        inet_pton(AF_INET, ip.c_str(), &(server_address.sin_addr));

        sendto(our_socket, packet, sizeof(struct Packet),
               0, (const struct sockaddr *)&server_address,
               sizeof(server_address));
    }
}


void Network::broadcast(struct Packet *packet)
{
    for (std::string ip : this->active_ips)
    {
        std::cout << "Broadcasting to: " << ip << std::endl;
        sendPacket(ip, packet);
    }
}

void Network::addActiveIp(std::string ip)
{

    if (std::find(this->active_ips.begin(), this->active_ips.end(), ip) == this->active_ips.end())
    {
        // Let's save this active ip
        this->dnp_file->addIp(ip);
        this->active_ips.push_back(ip);
        struct Packet packet;
        createActiveIpPacket(ip, &packet);
        broadcast(&packet);
    }
}

bool Network::isActiveIp(std::string ip)
{
    for (std::string _ip : this->active_ips)
    {
        if (_ip == ip)
            return true;
    }

    return false;
}

void Network::createActiveIpPacket(std::string ip, struct Packet *packet)
{
    memset(packet, 0, sizeof(struct Packet));
    packet->type = PACKET_TYPE_ACTIVE_IP;
    memset(packet->active_ip_packet.ip_address, 0, ip.size());
    memcpy(packet->active_ip_packet.ip_address, ip.c_str(), ip.size());
}

void Network::handleIncomingPacket(struct sockaddr_in client_address, struct Packet *packet)
{
    try
    {
        switch (packet->type)
        {
        case PACKET_TYPE_INITIAL_HELLO:
            handleInitalHelloPacket(client_address, packet);
            break;

        case PACKET_TYPE_RESPOND_HELLO:
            handleHelloRespondPacket(client_address, packet);
            break;

        case PACKET_TYPE_ACTIVE_IP:
            handleActiveIpPacket(client_address, packet);
            break;

        case PACKET_TYPE_DATAGRAM:
            handleDatagramPacket(client_address, packet);
        break;
        case PACKET_TYPE_PING:
            // Do nothing ping recieved used to keep nat open
            break;
        }
    }
    catch (std::exception &ex)
    {
        // IO out for now but this should log into an error log internal logging mechnism
        std::cout << ex.what() << std::endl;
    }
}

void Network::handleInitalHelloPacket(struct sockaddr_in client_address, struct Packet *packet)
{
    char client_ip[INET_ADDRSTRLEN];
    memset(client_ip, 0, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(client_address.sin_addr), client_ip, INET_ADDRSTRLEN);
    std::string their_ip = std::string(client_ip, strnlen(client_ip, INET_ADDRSTRLEN));
    std::string my_ip = std::string(packet->hello_packet.your_ip, INET_ADDRSTRLEN);
    this->our_ip = my_ip;

    Packet packet_to_send = {0};
    packet_to_send.type = PACKET_TYPE_RESPOND_HELLO;
    memcpy(packet_to_send.hello_packet.your_ip, their_ip.c_str(), their_ip.size());
    sendPacket(their_ip, &packet_to_send);

    // Let's send all our known active ip's to this guy
    for (std::string ip : this->active_ips)
    {
        struct Packet packet;
        createActiveIpPacket(ip, &packet);
        sendPacket(their_ip, &packet);
    }
    addActiveIp(their_ip);
}

void Network::handleHelloRespondPacket(struct sockaddr_in client_address, struct Packet *packet)
{
    char client_ip[INET_ADDRSTRLEN];
    memset(client_ip, 0, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(client_address.sin_addr), client_ip, INET_ADDRSTRLEN);
    std::string their_ip = std::string(client_ip, strnlen(client_ip, INET_ADDRSTRLEN));
    std::string my_ip = std::string(packet->hello_packet.your_ip, strnlen(packet->hello_packet.your_ip, INET_ADDRSTRLEN));
    this->our_ip = my_ip;

    addActiveIp(their_ip);
}

void Network::handleActiveIpPacket(struct sockaddr_in client_address, struct Packet *packet)
{
    std::string active_ip = std::string(packet->active_ip_packet.ip_address, strnlen(packet->active_ip_packet.ip_address, INET_ADDRSTRLEN));
    addActiveIp(active_ip);
}


void Network::handleDatagramPacket(struct sockaddr_in client_address, struct Packet *packet)
{
    struct DnpDatagramPacket* datagram_packet = &packet->datagram_packet;
    std::string sender_address = std::string(datagram_packet->send_from.address, sizeof(datagram_packet->send_from.address));

    // If we are not a private key holder then we should not send this packet to the kernel
    if (!this->dnp_file->isPrivateKeyHolder(sender_address))
    {
        return;
    }
    // Let's ensure this packet has not been tampered with
    std::string public_key = std::string(datagram_packet->sender_public_key, strnlen(datagram_packet->sender_public_key, sizeof(datagram_packet->sender_public_key)));
    std::string public_key_hashed = md5_hex(public_key);
    if (sender_address != public_key_hashed)
    {
        throw std::logic_error("Sender address does not match the public key hashed, someone has tampered with this packet!");
    }
    
    int encrypted_data_hash_size = datagram_packet->data.hash.size;
    if (encrypted_data_hash_size > sizeof(datagram_packet->data.hash.hash))
        throw std::logic_error("Forged packet attempts to exceed hash bounds!");

    std::string encrypted_data_hash = std::string(datagram_packet->data.hash.hash, encrypted_data_hash_size); 
    std::string decrypted_data_hash = "";
    try
    {
        Rsa::decrypt_public(public_key, encrypted_data_hash, decrypted_data_hash);
    }
    catch(...)
    {
        throw std::logic_error("Failed to decrypt hash with public key, this sender is illegal!");
    }

    if (md5_hex(std::string(datagram_packet->data.buf, sizeof(datagram_packet->data.buf))) != decrypted_data_hash)
    {
        throw std::logic_error("This packet has tampered data");
    }
    
    CREATE_KERNEL_PACKET(kernel_packet, DNP_KERNEL_PACKET_TYPE_RECV_DATAGRAM);
    struct dnp_kernel_packet_recv_datagram* kernel_packet_recv_datagram = &kernel_packet.recv_datagram_packet;
    memcpy(kernel_packet_recv_datagram->send_from.address, datagram_packet->send_from.address, sizeof(datagram_packet->send_from.address));
    kernel_packet_recv_datagram->send_from.port = datagram_packet->send_from.port;
    memcpy(kernel_packet_recv_datagram->send_to.address, datagram_packet->send_to.address, sizeof(datagram_packet->send_to.address));
    kernel_packet_recv_datagram->send_to.port = datagram_packet->send_to.port;
    memcpy(kernel_packet_recv_datagram->buf, datagram_packet->data.buf, sizeof(datagram_packet->data.buf));
    this->system->getKernelClient()->sendPacketToKernel(kernel_packet);
}