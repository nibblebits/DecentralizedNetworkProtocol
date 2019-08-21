#include "dnp.h"
#include "network.h"
#include <iostream>

using namespace Dnp;
System::System()
{
}

System::~System()
{
}

void System::host()
{
    DnpFile dnp_file;
    dnp_file.openFile("./test.dnp");
    Network network(&dnp_file);

    network.begin();
    network.bindMyself();
    network.scan();
}