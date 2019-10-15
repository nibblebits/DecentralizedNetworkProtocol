#include "dnp.h"
#include "system.h"
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
    this->dnp_file = new DnpFile(this);
    this->network = new Network(this);
}

System::~System()
{
    delete this->dnp_file;
    delete this->network;
    delete this->thread_pool;
}


void System::host()
{
    this->thread_pool->start();
    dnp_file->openFile("./test.dnp");

    network->begin();
    network->bindMyself();
    network->scan();

}


DnpFile *System::getDnpFile()
{
    return this->dnp_file;
}

void System::process()
{
   
}
