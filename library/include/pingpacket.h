#ifndef PINGPACKET_H
#define PINGPACKET_H

#include "networkpacket.h"
#include <string>

namespace Dnp
{
    class Network;
    class PingPacket : public NetworkPacket
    {
        public:
            PingPacket(Network* network);
            virtual ~PingPacket();

            virtual void send(std::string ip);
    };
};

#endif