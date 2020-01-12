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
#ifndef NETWORK_H
#define NETWORK_H

#include "config.h"
#include "types.h"
#include "crypto/rsa.h"
#include "dnpmodshared.h"
#include <string>
#include <list>
#include <thread>
#include <atomic>
#include <mutex>
#include <memory>
#include <queue>
#include <vector>
#include <array>
#include <condition_variable>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "networkpacket.h"
#define MAX_PACKET_SIZE 65527
#define PORT_RANGE_START 30001
#define PORT_RANGE_END 30010
#define MAX_MESSAGE_SIZE 1024
#define MAX_HANDLED_PACKET_VECTOR_SIZE 50000

namespace Dnp
{
class DnpFile;

typedef unsigned int NETWORK_OBJECT_ID;
typedef unsigned char NETWORK_OBJECT_TYPE;
enum
{
    NETWORK_OBJECT_TYPE_TEST
};

typedef unsigned int PACKET_ID;
typedef unsigned short PACKET_TYPE;
enum
{
    PACKET_TYPE_INITIAL_HELLO,
    PACKET_TYPE_RESPOND_HELLO,
    PACKET_TYPE_ACTIVE_IP,
    PACKET_TYPE_PING,
    PACKET_TYPE_DATAGRAM,
    PACKET_TYPE_OBJECT_PUBLISH
};

struct _HelloPacket
{
    // The IP Of the person we are connecting to. Let them know who they are
    char your_ip[INET_ADDRSTRLEN];
    unsigned short your_ip_len;
};

/*
    * Sent to clients to tell them about a currently active ip.
    */
struct _ActiveIpPacket
{
    // The active IP
    char ip_address[INET_ADDRSTRLEN];
};

struct DnpAddress
{
    char address[DNP_ID_SIZE];
    unsigned short port;
};

struct NetworkObject
{
    NETWORK_OBJECT_ID id;
    NETWORK_OBJECT_TYPE type;
    unsigned short size;
    time_t created;
};

/**
 * Simple test object used for testing purposes
 */
struct TestNetworkObject
{
    struct NetworkObject obj;
    unsigned int payload;
};

struct DnpBufferData
{
    char buf[DNP_MAX_DATAGRAM_PACKET_SIZE];
    // Once decrypted contains original MD5 hash of buf or was tampered with
    struct DnpEncryptedHash ehash;
};

struct _DnpDatagramPacket
{
    struct DnpAddress send_from;
    struct DnpAddress send_to;
    struct DnpBufferData data;
    char sender_public_key[MAX_PUBLIC_KEY_SIZE];
};

struct DnpNetworkObjectPacket
{
    struct NetworkObject obj;
};

struct Packet
{
    PACKET_ID id;
    PACKET_TYPE type;
    union {
        // hello_packet used for both inital hello's and responses
        struct _HelloPacket hello_packet;
        struct _ActiveIpPacket active_ip_packet;
        struct _DnpDatagramPacket datagram_packet;
        struct DnpNetworkObjectPacket network_object_packet;
    };
};

class System;
class HelloPacket;
class Network
{
public:
    Network();
    Network(System *system);
    virtual ~Network();

    void begin();
    void scan();
    void bindMyself();

    template <typename T>
    std::unique_ptr<T> newPacket()
    {
        return std::make_unique<T>(this);
    }

    /**
     * Takes the given binary packet and returns an object representing the packet provided
     * Packet provided must have a valid type
     */
    std::unique_ptr<NetworkPacket> resurrect(struct Packet* packet);

    struct Packet createPacket(PACKET_TYPE type);
    void initNetworkObject(struct NetworkObject *obj);

    /**
     * Creates a simple random network object on the decentralized network
     */
    void createTestNetworkObject();

    void publishNetworkObject(struct NetworkObject *obj);
    void sendPacket(std::string ip, struct Packet *packet);
    void broadcast(struct Packet *packet);
    std::vector<std::string> &getActiveIps();

    static void makeEncryptedHash(struct DnpEncryptedHash *out, const char *hash, DATA_HASH_SIZE size);

private:
    long getRandomIdUsingDefaultOffset();
    bool hasHandledPacket(struct Packet *packet);
    void markPacketHandled(struct Packet *packet);
    void ping();
    void sendHelloPacket(std::string to);
    void addActiveIp(std::string ip);
    bool isActiveIp(std::string ip);
    void handleIncomingPacket(struct sockaddr_in client_address, struct Packet *packet);
    void handleInitalHelloPacket(struct sockaddr_in client_address, HelloPacket* packet);
    void handleHelloRespondPacket(struct sockaddr_in client_address, struct Packet *packet);
    void handleActiveIpPacket(struct sockaddr_in client_address, struct Packet *packet);
    void handleDatagramPacket(struct sockaddr_in client_address, struct Packet *packet);
    void handleNetworkObjectPublishPacket(struct sockaddr_in client_address, struct Packet *packet);

    int get_valid_socket(struct sockaddr_in *servaddr);
    static void network_recv_thread_operation(Network *network);
    static void network_general_thread_operation(Network *network);

    void network_recv_thread_run();
    void network_general_thread_run();
    std::vector<std::string> known_ips;
    std::vector<std::string> active_ips;
    std::thread network_recv_thread;
    std::thread network_general_thread;

    std::mutex thread_lock;
    std::condition_variable binded_cv;
    bool is_binded;
    int our_socket;
    struct sockaddr_in our_address;
    // Our remote ip address, blank until we receive a hello packet
    std::string our_ip;

    // Our DNP file where we will be storing data to
    DnpFile *dnp_file;

    System *system;

    /**
     * This is the offset that will be used for all id's its incremented every time its used
     */
    std::atomic_long offset;

    // The Id's of all the packets that have already been handled and received
    std::list<unsigned long> handled_packets;

    /**
     * Each network object in this array is in char form so should be casted to the correct type
     */
    std::vector<std::unique_ptr<char[]>> network_objects;
};
} // namespace Dnp

#endif