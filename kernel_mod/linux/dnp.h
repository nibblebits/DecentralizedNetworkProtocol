#ifndef DNP_H
#define DNP_H

#include <net/sock.h>
#include <linux/module.h>


#define DNP_FAMILY 43
#define DNP_DATAGRAM_PROTOCOL 0
#define DNP_MAX_PROTOCOLS 1
#define DNP_MAX_OPTIONS 4

#define SOCKET_OPTION_VALUE_INTEGER 0
#define SOCKET_OPTION_VALUE_BUFFER 1
typedef int SOCKET_OPTION_VALUE_TYPE;

#define DNP_SOCKET_OPTION_MUST_DELIVER 0

struct dnp_socket_option
{
	union 
	{
		int ival;
		char* sval;
	};
};

struct dnp_dnpdatagramsock
{
    struct sock sk;
	struct dnp_socket_option options[DNP_MAX_OPTIONS];
};

#define dnp_dnpdatagramsock(sk) ((struct dnp_dnpdatagramsock *) sk)


struct dnp_protocol {
	int id;
	struct proto *proto;
	int (*create)(struct net *net, struct socket *sock,
		      const struct dnp_protocol *dnp_proto, int kern);
};



int dnpdatagramprotocol_init(void);
void dnpdatagramprotocol_exit(void);

int dnp_family_init(void);
void dnp_family_exit(void);
int dnp_proto_register(const struct dnp_protocol *dnp_proto);
void dnp_proto_unregister(const struct dnp_protocol *dnp_proto);



#endif