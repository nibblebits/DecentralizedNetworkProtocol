#include "dnpfamily.h"
#include "dnp.h"
#include <net/sock.h>


static DEFINE_RWLOCK(proto_tab_lock);
static const struct dnp_protocol *proto_tab[DNP_MAX_PROTOCOLS];


static int dnp_sock_create(struct net *net, struct socket *sock, int proto,
			   int kern)
{
	int rc = -EPROTONOSUPPORT;

	if (net != &init_net)
		return -EAFNOSUPPORT;

	if (proto < 0 || proto >= DNP_MAX_PROTOCOLS)
		return -EINVAL;

	read_lock(&proto_tab_lock);
	if (proto_tab[proto]) {
		rc = proto_tab[proto]->create(net, sock, proto_tab[proto], kern);
	}
	read_unlock(&proto_tab_lock);

    printk(KERN_INFO "dnp_sock_create: Creating socket");
	return rc;
}



static const struct net_proto_family dnp_sock_family_ops = {
	.owner  = THIS_MODULE,
	.family = DNP_FAMILY,
	.create = dnp_sock_create,
};


int dnp_proto_register(const struct dnp_protocol *dnp_proto)
{
	int rc;

	if (dnp_proto->id < 0 || dnp_proto->id >= DNP_MAX_PROTOCOLS)
		return -EINVAL;

	rc = proto_register(dnp_proto->proto, 0);
	if (rc)
		return rc;

	write_lock(&proto_tab_lock);
	if (proto_tab[dnp_proto->id])
		rc = -EBUSY;
	else
		proto_tab[dnp_proto->id] = dnp_proto;
	write_unlock(&proto_tab_lock);

	return rc;
}

void dnp_proto_unregister(const struct dnp_protocol *dnp_proto)
{
	write_lock(&proto_tab_lock);
	proto_tab[dnp_proto->id] = NULL;
	write_unlock(&proto_tab_lock);

	proto_unregister(dnp_proto->proto);
}


int dnp_family_init(void)
{
    printk(KERN_INFO "dnp_family_init()");
    return sock_register(&dnp_sock_family_ops);
}

void dnp_family_exit(void)
{
    printk(KERN_INFO "dnp_family_exit()");
}

