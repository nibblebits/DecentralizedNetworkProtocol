#include <iostream>
#include <memory.h>
#include "dnp.h"

using namespace Dnp;

/**
* This is a test app for testing DNP network
 */
int main()
{

  Dnp::System dnp;
  dnp.use();
  dnp.test_ping();

  std::cout << "testing" << std::endl;

  Cell cell = dnp.createCell();
  cell.setData("testing 4444", 4);
  cell.publish();

  std::cout << "cell published" << std::endl;
 
  
  return 0;
}