#include <iostream>
#include <memory.h>
#include "dnp.h"
#include "dnpfile.h"
#include "cell.h"
using namespace Dnp;

void createDnpFile()
{
  DnpFile dnp_file;
  dnp_file.openFile("./test.dnp");
  Dnp::System dnp;
  Cell cell(&dnp);
  cell.setId(3782917);
  cell.setData("Hello world", 12);
  cell.setFlags(CELL_FLAG_DATA_LOCAL);
  dnp_file.createCell(&cell);

int i = 0;
try
{
  while(1)
  {
    i++;
  cell.setId(32323223+i);
  cell.setData("This is cool", 13);
  cell.setFlags(CELL_FLAG_DATA_LOCAL);
  dnp_file.createCell(&cell);
  }
} catch(...)
{
  
}

  std::cout << "Total created: " << i << std::endl;

  cell.setId(32321132);
  cell.setData("This is cool", 13);
  cell.setFlags(CELL_FLAG_DATA_LOCAL);
  dnp_file.createCell(&cell);
  //dnp_file.createCell(5, 5, "hello world");

/*   dnp_file.addIp("178.62.113.46");

  std::string ip_str;
  unsigned long current_index = 0;
  while(dnp_file.getNextIp(ip_str, &current_index))
  {
  }*/



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

