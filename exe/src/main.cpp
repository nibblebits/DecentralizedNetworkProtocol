#include <iostream>
#include <memory.h>
#include "dnp.h"
#include "dnpfile.h"
int main(int argc, char** argv)
{
    Dnp::System dnp;
    dnp.host();

    Dnp::DnpFile loader;
    loader.openFile("./test.dnp");
    const char* data = "hello";
    loader.createNode(1, strlen(data), data);

    //loader.createNode(1, strlen(data), data);

    // We never want to die
    //while(1)
    {

    }
    return 0;
}