
#include "dnpkernelclient.h"
#include "system.h"
#include <unistd.h>
#include <iostream>

using namespace Dnp;

DnpKernelClient::DnpKernelClient(System* system)
{
    this->system = system;
}

DnpKernelClient::~DnpKernelClient()
{
    if (this->thread.joinable())
        this->thread.join();
}

void DnpKernelClient::start()
{
    start_thread();
}

void DnpKernelClient::start_thread()
{
    std::cout << "thread started" << std::endl;
    this->thread = std::thread(&DnpKernelClient::run, this);
}