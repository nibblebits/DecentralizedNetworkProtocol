#include <iostream>
#include <memory.h>
#include "dnp.h"
#include "dnpfile.h"

using namespace Dnp;
int main(int argc, char** argv)
{
    Dnp::System dnp;
//    dnp.host();

    Dnp::DnpFile loader;
    loader.openFile("./test.dnp");
    const char* data = "hello";
  // loader.createCell(1, strlen(data), data);
    //loader.createCell(2, strlen(data), data);
    


    char* abc = NULL;
    struct cell_header cell_header;
    bool ok = loader.loadCell((CELL_ID) 2, &cell_header, &abc);
    std::cout << "Was ok? " << ok << std::endl;

    std::cout << "Resolved cell with id: " << cell_header.id << std::endl;

    std::cout << "Data is: " << abc << std::endl;

    //loader.createCell(1, strlen(data), data);

    // We never want to die
    //while(1)
    {

    }
    return 0;
}