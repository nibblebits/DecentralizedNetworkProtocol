#include "dnp.h"
#include "network.h"
#include <iostream>

using namespace Dnp;
System::System()
{
    this->network = std::make_unique<Network>();
}

System::~System()
{

}


void System::host()
{
    network->begin();
    network->bindMyself();
    network->useIPFile("./ips.txt");
    network->scan();
}