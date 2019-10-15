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

#include "cell.h"
#include "config.h"
#include "types.h"
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_PACKET_SIZE 65527
#define PORT_RANGE_START 30001
#define PORT_RANGE_END 30010
#define MAX_MESSAGE_SIZE 1024

namespace Dnp
{
    class DnpFile;

    typedef unsigned short PACKET_TYPE;
    enum
    {
        PACKET_TYPE_INITIAL_HELLO,
        PACKET_TYPE_RESPOND_HELLO,
        PACKET_TYPE_ACTIVE_IP,
        PACKET_TYPE_PING,
    };

    struct HelloPacket
    {
        // The IP Of the person we are connecting to. Let them know who they are
        char your_ip[INET_ADDRSTRLEN];
        unsigned short your_ip_len;
    };

    /*
    * Sent to clients to tell them about a currently active ip.
    */
    struct ActiveIpPacket
    {
        // The activated IP
        char ip_address[INET_ADDRSTRLEN];
    };


  

    struct Packet
    {
        PACKET_TYPE type;
        union
        {
            struct HelloPacket hello_packet;
            struct ActiveIpPacket active_ip_packet;
        };
    };


    class Network
    {
    public:
        Network();
        Network(System* system);
        virtual ~Network();

        void begin();
        void scan();
        void bindMyself();

        void sendPacket(std::string ip, struct Packet* packet);

        void broadcast(struct Packet* packet);

    private:
        void ping();
        void addActiveIp(std::string ip);
        bool isActiveIp(std::string ip);
        void handleIncomingPacket(struct sockaddr_in client_address, struct Packet* packet);
        void handleInitalHelloPacket(struct sockaddr_in client_address, struct Packet* packet);
        void handleHelloRespondPacket(struct sockaddr_in client_address, struct Packet* packet);
        void handleActiveIpPacket(struct sockaddr_in client_address, struct Packet* packet);


        void createActiveIpPacket(std::string ip, struct Packet* packet);
        int get_valid_socket(struct sockaddr_in* servaddr);
        static void network_recv_thread_operation(Network* network);
        static void network_general_thread_operation(Network* network);

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
        DnpFile* dnp_file;

        System* system;

    };
}

#endif