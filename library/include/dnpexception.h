#ifndef DNPEXCEPTION_H

#include <stdexcept>
#include <string>

typedef unsigned short DNP_EXCEPTION_TYPE;

enum
{
    DNP_EXCEPTION_UNKNOWN,
    DNP_EXCEPTION_ILLEGAL_CELL,
    DNP_EXCEPTION_UNSUPPORTED
};

namespace Dnp
{
class DnpException : public std::logic_error
{
    public:
    DnpException(DNP_EXCEPTION_TYPE exception_type=DNP_EXCEPTION_UNKNOWN);
    DnpException(DNP_EXCEPTION_TYPE exception_type, std::string message);
    virtual ~DnpException();

    DNP_EXCEPTION_TYPE getExceptionType();
    private:
    DNP_EXCEPTION_TYPE exception_type;
};

}; // namespace Dnp

#endif