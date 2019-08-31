#include "dnp.h"
#include "system.h"
#include "network.h"
#include "threadpool.h"
#include "mmapcell.h"
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
    this->client_socket = nullptr;
}

System::~System()
{
    delete this->dnp_file;
    delete this->network;
    delete this->thread_pool;
}

std::fstream f;
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

    process_cells_waiting_for_processing();
    network->begin();
    network->bindMyself();
    network->scan();

    this->server_socket = std::make_unique<ServerDomainSocket>(this);
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

ClientDomainSocket* System::getClientDomainSocket()
{
    if (this->client_socket == nullptr)
    {
        throw std::logic_error("client_socket is NULL did you call host()? This method is for use() only");
    }

    return this->client_socket;
}

void System::process()
{
    if (this->client_socket != nullptr)
    {
        this->client_socket->process();
    }
}

void System::process_cells_waiting_for_processing()
{
    // Let's read from the file and find cells that are waiting to be published
    struct file_header header;
    this->dnp_file->getFileHeader(&header);

    std::cout << "Total cells: " << header.total_cells << std::endl;
    
    MemoryMappedCell cell(this);
    CELL_POSITION pos = header.last_cell;
    while(this->dnp_file->iterateBackwards(&cell, &pos))
    {
        std::cout << "Cell id: " << cell.getId() << std::endl;
        if (cell.getFlags() & CELL_FLAG_DATA_LOCAL)
        {
            std::cout << "It works? : " << cell.getData() << std::endl;
        }
        std::cout << "abcdf" << std::endl;
        
    }
}

void System::client_init_connect()
{
    // Connect to this domain server
    this->client_socket = new ClientDomainSocket(this);
    this->client_socket->connectToServer();
}

void System::addCellForProcessing(Cell& cell)
{
   this->dnp_file->createCell(&cell);
}

Cell System::createCell()
{
    srand(time(NULL));
    unsigned int random_id = rand() % 5000;
    Cell cell(random_id, this);
    cell.setFlags(CELL_FLAG_NOT_PUBLISHED);
    return cell;
}