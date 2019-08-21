#include <iostream>
#include <memory.h>
#include "dnp.h"
#include "dnpfile.h"

using namespace Dnp;
int main(int argc, char **argv)
{
  Dnp::System dnp;
  //    dnp.host();

  Dnp::DnpFile loader;
  loader.openFile("./test.dnp");
  for (int i = 0; i < 200; i++)
  {
    loader.addIp("82.32.10.4");
  }

  std::string ip_str;
  unsigned long current_index = 0;
  for (int i = 0; i < 2; i++)
  {
    if(!loader.getNextIp(ip_str, &current_index))
    {
      std::cout << "IP ADD HAS FAILED" << std::endl;
    }
    std::cout << "Next ip is: " << ip_str << std::endl;
  }

  return 0;
}