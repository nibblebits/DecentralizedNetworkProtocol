#ifndef DNP_H
#define DNP_H

#include <net/sock.h>
#include <linux/module.h>
#include "dnpmodshared.h"

#define ENSURE_KERNEL_BINDED if (!dnp_kernel_server_binded_to_pid()) return -EUNATCH;
#define NEW_DNP_KERNEL_PACKET(name, type) struct dnp_kernel_packet* name = (struct dnp_kernel_packet*) kmalloc(sizeof(struct dnp_kernel_packet), GFP_USER); dnp_kernel_server_new_packet(type, name);
#define FREE_DNP_KERNEL_PACKET(name) kfree(name);

typedef int DNP_SOCKET_OPTION_VALUE_TYPE;

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
void dnp_kernel_server_init(void);
void dnp_kernel_server_exit(void);
bool dnp_kernel_server_binded_to_pid(void);
int dnp_kernel_server_send_packet_to_pid(struct dnp_kernel_packet *packet, __u32 _pid);
int dnp_kernel_server_send_packet(struct dnp_kernel_packet *packet);
void dnp_kernel_server_new_packet(DNP_KERNEL_PACKET_TYPE type, struct dnp_kernel_packet* packet);


#endif