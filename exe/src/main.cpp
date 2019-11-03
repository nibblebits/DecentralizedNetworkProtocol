#include <iostream>
#include <string>
#include <memory.h>
#include "dnp.h"
#include "dnpfile.h"
#include "crypto/rsa.h"
#include "dnpexception.h"
using namespace Dnp;

void createDnpFile()
{
  Dnp::System dnp;
  DnpFile dnp_file(&dnp);
  dnp_file.openFile("./test.dnp");
  // Create very first DNP address (Global DNP Address) will be used when no address is provided when sending packets
  struct rsa_keypair keypair = Rsa::generateKeypair();
  std::cout << "PUB KEY HASH: " << keypair.pub_key_md5_hash << std::endl;
  dnp_file.addDnpAddress(keypair.pub_key_md5_hash, keypair.pub_key, keypair.private_key);
  //dnp_file.addIp("178.62.113.46");
  
}

void host()
{
    Dnp::System dnp;
    try
    {
      dnp.host();
    }
    catch(const DnpException& ex)
    {
      std::cout << ex.what() << std::endl;
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

