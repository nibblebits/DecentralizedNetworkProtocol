#include <iostream>
#include <string>
#include <memory.h>
#include "dnp.h"
#include "dnpfile.h"
#include "cell.h"
using namespace Dnp;

void createDnpFile()
{
  Dnp::System dnp;
  DnpFile dnp_file(&dnp);
  dnp_file.openFile("./test.dnp");
  Cell cell = dnp.createCell();
  cell.setId("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  cell.setData("Hello world", 12);
//  cell.publish();
  
  
  dnp_file.createCell(&cell);


  MemoryMappedCell new_cell(&dnp);
  dnp_file.loadCell("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", new_cell);
  std::cout << new_cell.getData() << std::endl;
  std::cout << new_cell.getPrivateKey() << std::endl;
}

void host()
{
    Dnp::System dnp;
    dnp.host();

    while(1)
    { 
      dnp.process();
    }
}
int main(int argc, char **argv)
{

  if (argc > 1)
  {
    std::string action = std::string(argv[1]);
    if (action == "create")
    {
      createDnpFile();
    }
    else if(action == "host")
    {
      host();
    }
    else
    {
      std::cout << "You must provide an action" << std::endl;
    }
  }

  return 0;
}

