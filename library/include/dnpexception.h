#ifndef DNPEXCEPTION_H

#include <stdexcept>
#include <string>

typedef unsigned short DNP_EXCEPTION_TYPE;

enum
{
    DNP_EXCEPTION_UNKNOWN,
    DNP_EXCEPTION_KERNEL_CLIENT_BIND_FAILURE,
    DNP_EXCEPTION_KERNEL_CLIENT_PACKET_SEND_FAILURE,
    DNP_EXCEPTION_KERNEL_CLIENT_UNEXPECTED_PACKET_RESPONSE,
    DNP_EXCEPTION_KERNEL_CLIENT_HELLO_FAILURE,
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