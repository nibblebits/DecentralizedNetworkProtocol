#ifndef HELLORESPONDPACKET_H
#define HELLORESPONDPACKET_H

#include "networkpacket.h"
namespace Dnp
{
    class Network;
    class HelloRespondPacket: public NetworkPacket
    {
        public:
        HelloRespondPacket(Network* network);
        virtual ~HelloRespondPacket();
        void setTheirIp(std::string their_ip);

        virtual void send(std::string ip);
        private:
            std::string their_ip;
    };
};

#endif