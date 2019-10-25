
#include "dnpkernelclient.h"
#include <unistd.h>

using namespace Dnp;

DnpKernelClient::DnpKernelClient()
{
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
    this->thread = std::thread(&DnpKernelClient::run, this);
}