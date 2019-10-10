#ifndef DNP_H
#define DNP_H

#include <net/sock.h>


#define DNP_FAMILY 238
#define DNP_DATAGRAM_PROTOCOL 1
#define DNP_MAX_PROTOCOLS 1

struct dnp_dnpdatagramsock
{
    struct sock sk;
};

struct dnp_protocol {
	int id;
	struct proto *proto;
	int (*create)(struct net *net, struct socket *sock,
		      const struct dnp_protocol *dnp_proto, int kern);
};


#define dnp_dnpdatagramsock(sk) ((struct dnp_dnpdatagramsock *) sk)



#endif