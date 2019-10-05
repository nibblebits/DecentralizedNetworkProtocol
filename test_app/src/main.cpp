#include <iostream>
#include <memory.h>
#include "dnp.h"
#include "crypto/rsa.h"
using namespace Dnp;

/**
* This is a test app for testing DNP network
 */
int main()
{

  Dnp::System dnp;
  dnp.use();
  dnp.test_ping();

  //std::cout << "testing" << std::endl;
  
  Cell cell = dnp.createCell();
  cell.setData("testing 4444", sizeof("testing 4444"));
  cell.publish();


 // std::cout << "cell published" << std::endl;
  //std::cout << "cell id: " << cell.getId() << std::endl;
  
  while(1)
  {
    
  }
  return 0;
}