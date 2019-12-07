#ifndef DNPMODSHARED_H
#define DNPMODSHARED_H

#include <linux/socket.h>
#define NETLINK_DNP 31

#define DNP_FAMILY 43
#define DNP_DATAGRAM_PROTOCOL 0
#define DNP_MAX_PROTOCOLS 1
#define DNP_MAX_OPTIONS 4

#define DNP_ID_SIZE 32

#define SOCKET_OPTION_VALUE_INTEGER 0
#define SOCKET_OPTION_VALUE_BUFFER 1

#define DNP_SOCKET_OPTION_MUST_DELIVER 0

#define DNP_MAX_DATAGRAM_PACKET_SIZE 1024
#define __SOCK_SIZE__ 16 /* sizeof(struct sockaddr)	*/

typedef int DNP_SEMAPHORE_ID;
typedef unsigned char DNP_KERNEL_PACKET_TYPE;

enum
{
    DNP_KERNEL_PACKET_TYPE_HELLO,
    DNP_KERNEL_PACKET_TYPE_HELLO_RESPONSE,
    DNP_KERNEL_PACKET_TYPE_SEND_DATAGRAM,
    DNP_KERNEL_PACKET_TYPE_SEND_DATAGRAM_RESPONSE,
    DNP_KERNEL_PACKET_TYPE_CREATE_ID,
    DNP_KERNEL_PACKET_TYPE_CREATE_ID_RESPONSE,
    DNP_KERNEL_PACKET_TYPE_RECV_DATAGRAM,

};

enum
{
    DNP_KERNEL_SERVER_PID_OK,
    DNP_KERNEL_SERVER_PID_ALREADY_SET
};

typedef int DNP_KERNEL_SERVER_PID_RES;

enum
{
    DNP_KERNEL_SERVER_DATAGRAM_OK,
    DNP_KERNEL_SERVER_DATAGRAM_FAILED_ILLEGAL_ADDRESS,
    DNP_KERNEL_SERVER_DATAGRAM_FAILED_UNKNOWN,
};
typedef int DNP_KERNEL_SERVER_DATAGRAM_RES;


typedef int DNP_KERNEL_SERVER_DATAGRAM_FLAGS;

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

struct dnp_kernel_address
{
    char address[DNP_ID_SIZE];
    unsigned short port;
};


struct dnp_kernel_packet_recv_datagram
{
    struct dnp_kernel_address send_from;
    struct dnp_kernel_address send_to;
    // Data buffer containing the data to send
    char buf[DNP_MAX_DATAGRAM_PACKET_SIZE];
};


struct dnp_kernel_packet_datagram
{
    struct dnp_kernel_address send_from;
    struct dnp_kernel_address send_to;
    // Data buffer containing the data to send
    char buf[DNP_MAX_DATAGRAM_PACKET_SIZE];
    DNP_KERNEL_SERVER_DATAGRAM_FLAGS flags;
};

struct dnp_kernel_packet_datagram_res
{
    DNP_KERNEL_SERVER_DATAGRAM_RES res;
};

struct dnp_kernel_packet_create_id_packet
{
};

struct dnp_kernel_packet_create_id_res
{
    char created_id[DNP_ID_SIZE];
};

struct dnp_kernel_packet
{
    DNP_KERNEL_PACKET_TYPE type;
    DNP_SEMAPHORE_ID sem_id;
    union {
        struct dnp_kernel_packet_hello hello_packet;
        struct dnp_kernel_packet_hello_response hello_res_packet;
        struct dnp_kernel_packet_datagram datagram_packet;
        struct dnp_kernel_packet_datagram_res datagram_res_packet;
        struct dnp_kernel_packet_recv_datagram recv_datagram_packet;
        struct dnp_kernel_packet_create_id_packet create_id_packet;
        struct dnp_kernel_packet_create_id_res create_id_packet_res;
    };
};

typedef unsigned char DNP_ADDRESS_FLAGS;
enum
{
    DNP_ADDRESS_FLAG_GENERATE_ADDRESS = 0b00000001
};

struct dnp_address
{
    char *addr;
    unsigned short port;
    DNP_ADDRESS_FLAGS flags;
};

#define CREATE_KERNEL_PACKET(name, _type)                \
    struct dnp_kernel_packet name;                      \
    memset(&name, 0, sizeof(struct dnp_kernel_packet)); \
    name.type = _type;                                   \
    name.sem_id = -1;


#endif