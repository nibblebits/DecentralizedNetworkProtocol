/*
DNP Decentralized Network Protocol
Copyright (C) 2018 Daniel McCarthy

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


#ifndef SYSTEM_H
#define SYSTEM_H

#include <memory>
#include "network.h"
#include "dnpfile.h"
#include "types.h"
#include "cell.h"
#include "threadpool.h"
#include "clientdomainsocket.h"
#include "serverdomainsocket.h"

namespace Dnp
{


    class System
    {
    public:
        System();
        virtual ~System();
        void host();
        void use();
        /**
         * Pings the Dnp domain server to see if its active
         */
        void test_ping();

        /**
         * Returns the client domain socket if this socket uses a client_socket which would have been setup
         * upon calling use()
         */
        ClientDomainSocket* getClientDomainSocket();

        /**
         * Processes this DNP system instance
         */
        void process();
        
        /**
         * Creates a data cell on the DNP Network
         */
        Cell createCell();

        /**
         * Add's this cell to the DNP file for later processing
         */
        void addCellForProcessing(Cell& cell);
    private:

        void accept_socket_thread();
        DnpFile* dnp_file;
        Network* network;
        ThreadPool* thread_pool;

        // Below is used if this Dnp instance is used as a client and not a server
        void client_init_connect();
        ClientDomainSocket* client_socket;
        std::unique_ptr<ServerDomainSocket> server_socket;

    };
};
#endif