#include "dnp.h"
#include "system.h"
#include "dnplinuxkernelclient.h"
#include "misc.h"
#include "network.h"
#include "threadpool.h"
#include "dnpexception.h"
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
    this->thread_pool = new ThreadPool(4);
    this->dnp_file = new DnpFile(this);
    this->network = new Network(this);
    this->kernel_client = new DnpLinuxKernelClient(this);
}

System::~System()
{
    delete this->dnp_file;
    delete this->network;
    delete this->thread_pool;
    delete this->kernel_client;
}

void System::host()
{
    this->thread_pool->start();
    dnp_file->openFile("./test.dnp");

    network->begin();
    network->bindMyself();
    network->scan();

    kernel_client->start();

    while (1)
    {
        usleep(50);
    }
}

ThreadPool *System::getThreadPool()
{
    return this->thread_pool;
}

Network* System::getNetwork()
{
    return this->network;
}

DnpLinuxKernelClient* System::getKernelClient()
{
    return this->kernel_client;
}

DnpFile *System::getDnpFile()
{
    return this->dnp_file;
}

void System::process()
{
}
