#ifndef DNPMODSHARED_H
#define DNPMODSHARED_H

#define NETLINK_DNP 31

#define DNP_FAMILY 43
#define DNP_DATAGRAM_PROTOCOL 0
#define DNP_MAX_PROTOCOLS 1
#define DNP_MAX_OPTIONS 4

#define SOCKET_OPTION_VALUE_INTEGER 0
#define SOCKET_OPTION_VALUE_BUFFER 1

#define DNP_SOCKET_OPTION_MUST_DELIVER 0

#define DNP_MAX_DATAGRAM_PACKET_SIZE 1024

typedef unsigned char DNP_KERNEL_PACKET_TYPE;

enum
{
    DNP_KERNEL_PACKET_TYPE_HELLO,
    DNP_KERNEL_PACKET_TYPE_HELLO_RESPONSE,
    DNP_KERNEL_PACKET_TYPE_SEND_DATAGRAM
};


enum
{
    DNP_KERNEL_SERVER_PID_OK,
    DNP_KERNEL_SERVER_PID_ALREADY_SET
};

typedef int DNP_KERNEL_SERVER_PID_RES;

enum
{
    DNP_HELLO_RESPONSE_OK,
    DNP_HELLO_RESPONSE_PID_ALREADY_SET
};

typedef int DNP_HELLO_RESPONSE;

struct dnp_kernel_packet_hello
{
};

struct dnp_kernel_packet_hello_response
{
    DNP_HELLO_RESPONSE res;
};

struct dnp_kernel_packet_datagram
{
    char buf[DNP_MAX_DATAGRAM_PACKET_SIZE];
    
};


struct dnp_kernel_packet
{
    DNP_KERNEL_PACKET_TYPE type;
    union {
        struct dnp_kernel_packet_hello hello_packet;
        struct dnp_kernel_packet_hello_response hello_res_packet;
        struct dnp_kernel_packet_datagram datagram_packet;
    };
};

#endif