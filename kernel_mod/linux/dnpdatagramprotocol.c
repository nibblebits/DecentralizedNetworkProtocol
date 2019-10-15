#include "dnp.h"
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

int dnpdatagramsock_set_integer_option_for_userspace(struct dnp_dnpdatagramsock *dnp_sock, int optname, int __user *optval)
{
	int rc = 0;
	int val = -1;
	if (get_user(val, optval) != 0)
	{
		rc = -EIO;
		printk(KERN_ERR "Failed to get value from user space\n");
		goto out;
	}

	lock_sock(&dnp_sock->sk);
	dnp_sock->options[optname].ival = val;
	release_sock(&dnp_sock->sk);

out:
	return rc;
}

int dnpdatagramsock_setsockopt(struct socket *sock, int level, int optname,
							   char __user *optval, unsigned int optlen)
{
	int rc = 0;

	struct dnp_dnpdatagramsock *dnp_sock = dnp_dnpdatagramsock(sock->sk);
	switch (optname)
	{
	case DNP_SOCKET_OPTION_MUST_DELIVER:
		dnpdatagramsock_set_integer_option_for_userspace(dnp_sock, optname, (int __user *)optval);
		break;
	};

out:

	printk(KERN_INFO "dnpdatagramsock_setsockopt() complete\n");

	return rc;
}

int dnpdatagramsock_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
    char ipv4[32], *usermsg = NULL;
    struct iovec *iov = NULL;

    iov = msg->msg_iter.iov;
    usermsg = (char *)kmalloc(iov->iov_len, GFP_USER);
    memcpy(usermsg, iov->iov_base, iov->iov_len);
    printk(KERN_INFO "user msg = %s\n", usermsg);
    printk(KERN_INFO "msg->msg_iter.count (no of data bytes) = %d", msg->msg_iter.count);
    printk(KERN_INFO "iov_base = 0x%x, iov_len = %d\n", iov->iov_base, iov->iov_len);
    printk(KERN_INFO "msg->msg_iter.nr_segs (no of iovec segments) = %d", msg->msg_iter.nr_segs);
    kfree(usermsg);

	return 0;
}

int dnpdatagramsock_recvmsg(struct socket *sock, struct msghdr *m, size_t len,
		    int flags)
{
	return -EOPNOTSUPP;
}


static const struct proto_ops dnpdatagramsock_ops = {
	.family = DNP_FAMILY,
	.owner = THIS_MODULE,
	.release = dnpdatagramsock_release,
	.bind = sock_no_bind,
	.connect = sock_no_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.poll = sock_no_poll,
	.ioctl = sock_no_ioctl,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = dnpdatagramsock_setsockopt,
	.getsockopt = sock_no_getsockopt,
	.sendmsg = dnpdatagramsock_sendmsg,
	.recvmsg = dnpdatagramsock_recvmsg,
	.mmap = sock_no_mmap,
};

static void dnpdatagramsock_destruct(struct sock *sk)
{
	printk(KERN_INFO "dnpdatagramsock_destruct()");
}

static void dnpdatagramsock_init(struct dnp_dnpdatagramsock *sock)
{
	memset(sock->options, 0, sizeof(sock->options));
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

	// Initialize this socket
	dnpdatagramsock_init(dnp_dnpdatagramsock(sk));

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
	.create = dnpdatagramsock_create};

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