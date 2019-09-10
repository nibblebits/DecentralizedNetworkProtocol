#include <iostream>
#include <string>
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

  cell.setId("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  cell.setData("This is cool", 13);
  cell.setFlags(CELL_FLAG_DATA_LOCAL);
  dnp_file.createCell(&cell);

  struct cell_header cell_header;
  char* data;
  dnp_file.loadCell("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &cell_header, &data);

  std::cout << "Id: " << std::string((char*) &cell_header.id, MD5_HEX_SIZE) << std::endl;

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

