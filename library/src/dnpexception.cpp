#include "dnpexception.h"

using namespace Dnp;
DnpException::DnpException(DNP_EXCEPTION_TYPE exception_type) : DnpException(exception_type, "")
{
}

DnpException::DnpException(DNP_EXCEPTION_TYPE exception_type, std::string message) : std::logic_error(message)
{
    this->exception_type = exception_type;
}

DnpException::~DnpException()
{

}

DNP_EXCEPTION_TYPE DnpException::getExceptionType()
{
    return this->exception_type;
}