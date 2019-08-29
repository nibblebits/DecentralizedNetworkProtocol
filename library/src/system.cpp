#include "dnp.h"
#include "system.h"
#include "network.h"
#include "threadpool.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

using namespace Dnp;
System::System()
{
    this->dnp_file = new DnpFile();
    this->network = new Network(this->dnp_file);
    this->thread_pool = new ThreadPool(MAX_TOTAL_THREADS);
    this->client_socket = NULL;
}

System::~System()
{
    delete this->dnp_file;
    delete this->network;
    delete this->thread_pool;
}

void System::accept_socket_thread()
{
    while(1)
    {
        // Loop forever
        DomainSocket* socket = this->server_socket->acceptSocket();
    }
}
void System::host()
{
    this->thread_pool->start();
    dnp_file->openFile("./test.dnp");

    network->begin();
    network->bindMyself();
    network->scan();

    this->server_socket = std::make_unique<ServerDomainSocket>();
    this->server_socket->host();
    this->thread_pool->addTask([=] {
         accept_socket_thread();
    });
}

void start_domain_socket_client_thread();

void System::use()
{
    client_init_connect();
}

void System::test_ping()
{
    this->client_socket->sendPing();
}


void System::process()
{
    if (this->client_socket != nullptr)
    {
        this->client_socket->process();
    }
}

void System::client_init_connect()
{
    // Connect to this domain server
    this->client_socket = new ClientDomainSocket();
    this->client_socket->connectToServer();
}

Cell System::createCell()
{
    srand(time(NULL));
    unsigned int random_id = rand() % 5000;
    Cell cell(random_id, this);
    return cell;
}