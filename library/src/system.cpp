#include "dnp.h"
#include "system.h"
#include "misc.h"
#include "network.h"
#include "threadpool.h"
#include "mmapcell.h"
#include "crypto/rsa.h"
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
    this->dnp_file = new DnpFile(this);
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
    while (1)
    {
        // Loop forever
        DomainSocket *socket = this->server_socket->acceptSocket();
    }
}
void System::host()
{
    this->thread_pool->start();
    dnp_file->openFile("./test.dnp");

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

ClientDomainSocket *System::getClientDomainSocket()
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

    MemoryMappedCell cell(this);
    CELL_POSITION pos = header.last_cell;
    while (this->dnp_file->iterateBackwards(&cell, &pos))
    {
        CELL_FLAGS flags = cell.getFlags();
        // We only care about cells that are not yet published
        if (!(flags & CELL_FLAG_PUBLISHED))
        {
            // Let's mark this cell as published
            cell.setFlag(CELL_FLAG_PUBLISHED);
            if(!this->dnp_file->updateCell(cell))
            {
                throw std::logic_error("process_cells_waiting_for_processing(): failed to update cell");
            }
        }
    }
}

void System::client_init_connect()
{
    // Connect to this domain server
    this->client_socket = new ClientDomainSocket(this);
    this->client_socket->connectToServer();
}

void System::addCellForProcessing(Cell &cell)
{
    this->dnp_file->createCell(&cell);
}

Cell System::createCell()
{

    struct rsa_keypair keypair = Rsa::generateKeypair();
    Cell cell(keypair.pub_key_md5_hash, this);
    cell.setPublicKey(keypair.pub_key);
    cell.setPrivateKey(keypair.private_key);
    cell.setFlags(CELL_FLAG_PRIVATE_KEY_HOLDER);
    return cell;
}