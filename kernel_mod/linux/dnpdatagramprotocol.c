#include "dnpdatagramprotocol.h"
#include "dnp.h"
#include "dnpfamily.h"
#include <net/sock.h>


static int dnpdatagramsock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

    printk(KERN_INFO "dnpdatagramsock_release()");
	if (!sk)
		return 0;


	sock_orphan(sk);
	sock_put(sk);

	return 0;
}

static const struct proto_ops dnpdatagramsock_ops = {
	.family         = DNP_FAMILY,
	.owner          = THIS_MODULE,
	.release        = dnpdatagramsock_release,
	.bind           = sock_no_bind,
	.connect        = sock_no_connect,
	.socketpair     = sock_no_socketpair,
	.accept         = sock_no_accept,
	.getname        = sock_no_getname,
	.poll           = sock_no_poll,
	.ioctl          = sock_no_ioctl,
	.listen         = sock_no_listen,
	.shutdown       = sock_no_shutdown,
	.setsockopt     = sock_no_setsockopt,
	.getsockopt     = sock_no_getsockopt,
	.sendmsg        = sock_no_sendmsg,
	.recvmsg        = sock_no_recvmsg,
	.mmap           = sock_no_mmap,
};

static void dnpdatagramsock_destruct(struct sock *sk)
{
    printk(KERN_INFO "dnpdatagramsock_destruct()");
}


static int dnpdatagramsock_create(struct net *net, struct socket *sock,
			  const struct dnp_protocol *dnp_proto, int kern)
{
	struct sock *sk;

    printk(KERN_INFO "dnpdatagramsock_create()");

	sock->ops = &dnpdatagramsock_ops;

	sk = sk_alloc(net, DNP_FAMILY, GFP_ATOMIC, dnp_proto->proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	sk->sk_protocol = dnp_proto->id;
	sk->sk_destruct = dnpdatagramsock_destruct;
	sock->state = SS_UNCONNECTED;
	
	return 0;
}


static struct proto dnpdatagramsock_proto = {
    .name = "DNP_DATAGRAM_PROT",
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct dnp_dnpdatagramsock),
};

static const struct dnp_protocol dnpdatagram_proto = {
    .id = DNP_DATAGRAM_PROTOCOL,
    .proto = &dnpdatagramsock_proto,
    .create = dnpdatagramsock_create
};

int dnpdatagramprotocol_init(void)
{
    int rc;
    rc = dnp_proto_register(&dnpdatagram_proto);
    return rc;
}

void dnpdatagramprotocol_exit(void)
{
    dnp_proto_unregister(&dnpdatagram_proto);
}