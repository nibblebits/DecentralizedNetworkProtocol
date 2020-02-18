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
#include "networkpacket.h"
#include "pingpacket.h"
#include "hellopacket.h"
#include "hellorespondpacket.h"
#include "dnpdatagrampacket.h"
#include "activeippacket.h"
#include "testnetworkobject.h"
#include "clientgroupnetworkobject.h"
#include "networkobject.h"
#include "networkobjectmanager.h"
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
    this->dnp_file = system->getDnpFile();
    this->system = system;
    this->offset = time(NULL);
    this->object_manager = std::make_unique<NetworkObjectManager>();

    // Let's register some generic network objects that are used and held throughout the entire network
    this->object_manager->registerNetworkObject(std::make_unique<TestNetworkObject>(this));
    this->object_manager->registerNetworkObject(std::make_unique<ClientGroupNetworkObject>(this));
}

Network::~Network()
{
    if (this->network_recv_thread.joinable())
        this->network_recv_thread.join();

    if (this->network_general_thread.joinable())
        this->network_general_thread.join();
}

void Network::makeEncryptedHash(struct DnpEncryptedHash *out, const char *hash, DATA_HASH_SIZE size)
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
    struct Packet packet;
    while (1)
    {
        n = recvfrom(our_socket, (char *)&packet, MAX_PACKET_SIZE,
                     MSG_WAITALL, (struct sockaddr *)&client_address,
                     &len);

        // We don't care about packets who are not the right length.. Thats a disaster waiting to happen
        if (n != sizeof(packet))
            continue;
        handleIncomingPacket(client_address, &packet);
    }
}

void Network::ping()
{
    std::unique_ptr<NetworkPacket> packet = newPacket<PingPacket>();
    packet->broadcast();
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

long Network::getRandomIdUsingDefaultOffset()
{
    long result = 0;
    srand(time(NULL));
    result = offset + rand() % 0xffffffff;
    offset++;
    return result;
}
struct Packet Network::createPacket(PACKET_TYPE type)
{
    struct Packet packet;
    memset(&packet, 0, sizeof(struct Packet));
    packet.type = type;
    packet.id = getRandomIdUsingDefaultOffset();
    return packet;
}

void Network::sendHelloPacket(std::string to)
{
    // We should not send a hello packet if we they have already responded to a hello packet

    std::unique_ptr<HelloPacket> packet = newPacket<HelloPacket>();
    packet->setTheirIp(to);
    packet->send(to);
    std::cout << "Sent hello packet: " << to << std::endl;
}

void Network::scan()
{

    for (std::string ip : this->known_ips)
    {
        if (!isActiveIp(ip))
        {
            this->sendHelloPacket(ip);
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

void Network::sendObject(std::string ip, const char *buf, size_t size, NetworkObject *obj)
{

    Packet packet = this->createPacket(PACKET_TYPE_OBJECT_PUBLISH);
    struct NetworkObjectPacket *npacket = &packet.network_object_packet;
    struct _NetworkObject *nobject = &npacket->obj;
    // Copy payload to network packet
    memcpy(&nobject->data.buf, buf, size);

    std::string encrypted_data_hash = obj->getEncryptedDataHash();
    std::string private_key = obj->getPrivateKey();

    if (encrypted_data_hash.empty() && private_key.empty())
    {
        throw DnpException(DNP_EXCEPTION_PRIVATE_KEY_FAILURE, "Expecting a private key to be provided, or an existing encrypted data hash!");
    }

    std::string buf_str = std::string(nobject->data.buf, sizeof(nobject->data.buf));

    // Let's sign this data using our private key
    if (encrypted_data_hash.empty())
    {
        encrypted_data_hash = Rsa::makeEncryptedHash(buf_str, private_key, npacket->obj.data.ehash);
    }


    // Let's set the encrypted data hash in this object
    obj->setEncryptedDataHash(encrypted_data_hash);

    nobject->created = time(NULL);
    std::string id = obj->getId();
    if (id.empty())
    {
        throw DnpException(DNP_EXCEPTION_UNKNOWN, "Attempting to send a network object without an id. Did you forget to call generateId()");
    }

    std::string type = obj->getType();
    if (type.size() >= sizeof(nobject->type))
    {
        throw DnpException(DNP_EXCEPTION_UNKNOWN, "Size of type exceeds buffer");
    }

    if (id.size() != sizeof(nobject->id))
    {
        throw DnpException(DNP_EXCEPTION_UNKNOWN, "Size of id too small");
    }

    memcpy(nobject->id, id.c_str(), DNP_ID_SIZE);
    memcpy(nobject->type, type.c_str(), type.size());
    nobject->type_len = type.size();

    std::string public_key = obj->getPublicKey();
    memcpy(nobject->public_key, public_key.c_str(), public_key.size());

    sendPacket(ip, &packet);
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

std::vector<std::string> &Network::getActiveIps()
{
    return this->active_ips;
}

void Network::addActiveIp(std::string ip)
{
    if (std::find(this->active_ips.begin(), this->active_ips.end(), ip) == this->active_ips.end())
    {
        // Let's save this active ip
        this->dnp_file->addIp(ip);
        this->active_ips.push_back(ip);
    }

    std::unique_ptr<ActiveIpPacket> packet = newPacket<ActiveIpPacket>();
    packet->setIp(ip);
    packet->broadcast();
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

bool Network::hasHandledPacket(struct Packet *packet)
{
    for (long id : this->handled_packets)
    {
        if (id == packet->id)
            return true;
    }

    return false;
}

void Network::markPacketHandled(struct Packet *packet)
{
    // We only hold a maximum amount of handled packets, whole point of this system is to help reduce chance of mass broadcast in a loop
    if (this->handled_packets.size() > MAX_HANDLED_PACKET_VECTOR_SIZE)
        this->handled_packets.pop_front();

    this->handled_packets.push_back(packet->id);
}

NetworkObjectManager *Network::getObjectManager()
{
    return this->object_manager.get();
}

std::unique_ptr<NetworkPacket> Network::resurrect(struct Packet *packet)
{
    std::unique_ptr<NetworkPacket> npacket = nullptr;

    switch (packet->type)
    {
    case PACKET_TYPE_INITIAL_HELLO:
        npacket = HelloPacket::resurrect(this, packet);
        break;

    case PACKET_TYPE_RESPOND_HELLO:
        npacket = HelloRespondPacket::resurrect(this, packet);
        break;

    case PACKET_TYPE_DATAGRAM:
        npacket = DnpDatagramPacket::resurrect(this, packet);
        break;

    case PACKET_TYPE_ACTIVE_IP:
        npacket = ActiveIpPacket::resurrect(this, packet);
        break;

    case PACKET_TYPE_PING:
        npacket = PingPacket::resurrect(this, packet);
        break;

    case PACKET_TYPE_OBJECT_PUBLISH:
        npacket = NetworkObject::resurrect(this, packet);
        break;

    default:
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "Unsupported packet type: " + std::to_string(packet->type) + " cannot resurrect");
    }

    return npacket;
}

void Network::handleIncomingPacket(struct sockaddr_in client_address, struct Packet *packet)
{
    std::unique_ptr<NetworkPacket> npacket = nullptr;
    try
    {
        // If we already handled this packet then we should leave
        if (hasHandledPacket(packet))
        {
            return;
        }
        npacket = resurrect(packet);
        switch (packet->type)
        {
        case PACKET_TYPE_INITIAL_HELLO:
            handleInitalHelloPacket(client_address, static_cast<HelloPacket *>(npacket.get()));
            break;

        case PACKET_TYPE_RESPOND_HELLO:
            handleHelloRespondPacket(client_address, static_cast<HelloRespondPacket *>(npacket.get()));
            break;

        case PACKET_TYPE_ACTIVE_IP:
            handleActiveIpPacket(client_address, static_cast<ActiveIpPacket *>(npacket.get()));
            break;

        case PACKET_TYPE_DATAGRAM:
            handleDatagramPacket(client_address, static_cast<DnpDatagramPacket *>(npacket.get()));
            break;

        case PACKET_TYPE_OBJECT_PUBLISH:
            handle_NetworkObjectPublishPacket(client_address, packet);
            break;
        case PACKET_TYPE_PING:
            // Do nothing ping recieved used to keep nat open
            break;
        }

        markPacketHandled(packet);
    }
    catch (std::logic_error &ex)
    {
        // IO out for now but this should log into an error log internal logging mechnism
        std::cout << ex.what() << std::endl;
    }
}

void Network::handleInitalHelloPacket(struct sockaddr_in client_address, HelloPacket *packet)
{
    // The hello packet has told us our IP address let's get it
    this->our_ip = packet->getTheirIp();

    std::cout << "Our ip=" << this->our_ip.toString() << std::endl;

    // Let's get the real IP address of the person who sent this packet to us.
    char client_ip[INET_ADDRSTRLEN];
    memset(client_ip, 0, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(client_address.sin_addr), client_ip, INET_ADDRSTRLEN);
    std::string their_ip = std::string(client_ip, strnlen(client_ip, INET_ADDRSTRLEN));

    std::cout << "Client address: " << their_ip << std::endl;

    // Only respond to this hello if they are not in our active IP list already
    if (!isActiveIp(their_ip))
    {
        std::unique_ptr<HelloRespondPacket> packet = newPacket<HelloRespondPacket>();
        packet->setTheirIp(their_ip);
        packet->send(their_ip);
    }

    // Let's send all our known active ip's to this guy
    for (std::string ip : this->active_ips)
    {
        std::unique_ptr<ActiveIpPacket> packet = newPacket<ActiveIpPacket>();
        packet->setIp(ip);
        packet->send(their_ip);
    }
    addActiveIp(their_ip);
}

void Network::handleHelloRespondPacket(struct sockaddr_in client_address, struct HelloRespondPacket *packet)
{
    char client_ip[INET_ADDRSTRLEN];
    memset(client_ip, 0, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(client_address.sin_addr), client_ip, INET_ADDRSTRLEN);
    std::string their_ip = std::string(client_ip, strnlen(client_ip, INET_ADDRSTRLEN));
    this->our_ip = packet->getTheirIp();

    addActiveIp(their_ip);
}

void Network::handleActiveIpPacket(struct sockaddr_in client_address, struct ActiveIpPacket *packet)
{
    std::string active_ip = packet->getIp();
    // Let's say hello to this IP we have just been made aware of if they respond we will add them as an active IP
    if (!isActiveIp(active_ip))
    {
        sendHelloPacket(active_ip);
    }
}

void Network::handleDatagramPacket(struct sockaddr_in client_address, struct DnpDatagramPacket *packet)
{
    std::cout << "Handle datagram packet called" << std::endl;
    DnpAddress sender_address = packet->getFromAddress();
    DnpAddress receiver_address = packet->getToAddress();

    std::string sender_address_str = std::string(sender_address.address, sizeof(sender_address.address));
    std::string receiver_address_str = std::string(receiver_address.address, sizeof(receiver_address.address));

    // If we are not a private key holder then we should not send this packet to the kernel
    if (!this->dnp_file->isPrivateKeyHolder(receiver_address_str))
    {
        return;
    }

    // Let's ensure this packet has not been tampered with
    std::string public_key = packet->getPublicKey();
    std::string public_key_hashed = md5_hex(public_key);
    if (sender_address_str != public_key_hashed)
    {
        throw std::logic_error("Sender address does not match the public key hashed, someone has tampered with this packet!");
    }

    struct DnpEncryptedHash ehash = packet->getEncryptedDataHash();
    int encrypted_data_hash_size = ehash.size;
    if (encrypted_data_hash_size > sizeof(ehash.hash))
        throw std::logic_error("Forged packet attempts to exceed hash bounds!");

    std::string encrypted_data_hash = std::string(ehash.hash, encrypted_data_hash_size);
    std::string decrypted_data_hash = "";
    try
    {
        Rsa::decrypt_public(public_key, encrypted_data_hash, decrypted_data_hash);
    }
    catch (...)
    {
        throw std::logic_error("Failed to decrypt hash with public key, this sender is illegal!");
    }

    std::string data = packet->getData();
    if (md5_hex(data) != decrypted_data_hash)
    {
        throw std::logic_error("This packet has tampered data");
    }

    CREATE_KERNEL_PACKET(kernel_packet, DNP_KERNEL_PACKET_TYPE_RECV_DATAGRAM);
    struct dnp_kernel_packet_recv_datagram *kernel_packet_recv_datagram = &kernel_packet.recv_datagram_packet;
    memcpy(kernel_packet_recv_datagram->send_from.address, sender_address.address, sizeof(sender_address.address));
    kernel_packet_recv_datagram->send_from.port = sender_address.port;
    memcpy(kernel_packet_recv_datagram->send_to.address, receiver_address.address, sizeof(receiver_address.address));
    kernel_packet_recv_datagram->send_to.port = receiver_address.port;
    memcpy(kernel_packet_recv_datagram->buf, data.c_str(), data.size());
    this->system->getKernelClient()->sendPacketToKernel(kernel_packet);

    std::cout << "Handle datagram packet success" << std::endl;
}

void Network::handle_NetworkObjectPublishPacket(struct sockaddr_in client_address, struct Packet *packet)
{
}