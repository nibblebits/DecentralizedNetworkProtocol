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
  dnp_file.addIp("178.62.113.46");
  
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

