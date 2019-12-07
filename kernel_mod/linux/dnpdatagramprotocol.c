#include "dnp.h"
#include "dnpmodshared.h"
#include <net/sock.h>

LIST_HEAD(root_port_list);
DEFINE_MUTEX(port_list_mutex);

LIST_HEAD(sock_list);
DEFINE_MUTEX(sock_list_mutex);

static int dnpdatagramsock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	printk(KERN_INFO "dnpdatagramsock_release()");
	if (!sk)
		return 0;

	mutex_lock(&sock_list_mutex);
	dnp_remove_socket(&sock_list, sock);
	mutex_unlock(&sock_list_mutex);
	mutex_lock(&port_list_mutex);
	dnp_remove_port(&root_port_list, sock);
	mutex_unlock(&port_list_mutex);

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
	ENSURE_KERNEL_BINDED

	int rc = 0;

	struct dnp_dnpdatagramsock *dnp_sock = dnp_dnpdatagramsock(sock->sk);
	switch (optname)
	{
	case DNP_SOCKET_OPTION_MUST_DELIVER:
		dnpdatagramsock_set_integer_option_for_userspace(dnp_sock, optname, (int __user *)optval);
		break;
	};

	printk(KERN_INFO "dnpdatagramsock_setsockopt() complete\n");

	return rc;
}

int dnpdatagramsock_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	ENSURE_KERNEL_BINDED

	if (!msg->msg_name)
	{
		printk(KERN_ERR "%s sending message without destination address is not allowed! msg_name is NULL\n", __FUNCTION__);
		return -EDESTADDRREQ;
	}

	struct dnp_address *dnp_address = (struct dnp_address *)msg->msg_name;
	if (dnp_address->addr == NULL)
	{
		printk(KERN_ERR "%s dnp_address->addr is NULL\n", __FUNCTION__);
		return -EINVAL;
	}

	char send_to_addr[DNP_ID_SIZE];
	if (copy_from_user(send_to_addr, dnp_address->addr, sizeof(send_to_addr)) != 0)
	{
		printk(KERN_ERR "%s failed to copy data from user process\n", __FUNCTION__);
		return -EINVAL;
	}

	int err = 0;
	struct iovec *iov = (struct iovec *)msg->msg_iter.iov;
	NEW_DNP_KERNEL_PACKET(res_packet, -1)
	NEW_DNP_KERNEL_PACKET(packet, DNP_KERNEL_PACKET_TYPE_SEND_DATAGRAM)
	memcpy(&packet->datagram_packet.buf, iov->iov_base, iov->iov_len);
	memcpy(packet->datagram_packet.send_from.address, dnp_dnpdatagramsock(sock)->addr, sizeof(packet->datagram_packet.send_from));
	packet->datagram_packet.send_from.port = dnp_dnpdatagramsock(sock)->port;

	err = dnp_kernel_server_send_and_wait(packet, res_packet);
	if (err < 0)
	{
		printk(KERN_ERR "%s failed to send packet to kernel server has it crashed? err=%i\n", __FUNCTION__, err);
		goto out;
	}

	if (res_packet->type != DNP_KERNEL_PACKET_TYPE_SEND_DATAGRAM_RESPONSE)
	{
		printk(KERN_ERR "%s response packet was not a DNP_KERNEL_SERVER_DATAGRAM_RES packet type, is this kernel server built for this module?\n", __FUNCTION__);
		err = -EPROTO;
		goto out;
	}

	if (res_packet->datagram_res_packet.res != DNP_KERNEL_SERVER_DATAGRAM_OK)
	{
		printk(KERN_ERR "%s failed to send datagram response_code=%i\n", __FUNCTION__, (int)res_packet->datagram_res_packet.res);
		err = -EINVAL;
		goto out;
	}
out:
	FREE_DNP_KERNEL_PACKET(res_packet)
	FREE_DNP_KERNEL_PACKET(packet)

	return err;
}

int dnpdatagramsock_recvmsg(struct socket *sock, struct msghdr *m, size_t len,
							int flags)
{
	ENSURE_KERNEL_BINDED

	return -EOPNOTSUPP;
}

int dnpdatagramsock_bind(struct socket *sock, struct sockaddr *saddr, int len)
{
	// Ensures the kernel is binded to the user host application that is running our DNP server (unrelated to this call)
	ENSURE_KERNEL_BINDED

	if (len != sizeof(struct dnp_address))
	{
		printk(KERN_ERR "%s Expecting a struct dnp_address but an unexpected type was provided to us len=%i expected_len=%i\n ", __FUNCTION__, len, (int)sizeof(struct dnp_address));
		return -EINVAL;
	}

	struct dnp_address *dnp_address = (struct dnp_address *)saddr;
	if (dnp_address->addr == NULL)
	{
		printk(KERN_ERR "%s dnp_address->addr is NULL\n", __FUNCTION__);
		return -EINVAL;
	}

	int err = 0;
	char addr[DNP_ID_SIZE];
	if (copy_from_user(addr, dnp_address->addr, sizeof(addr)) != 0)
	{
		printk(KERN_ERR "%s failed to copy data from user process\n", __FUNCTION__);
		return -EINVAL;
	}

	if (dnp_address->flags & DNP_ADDRESS_FLAG_GENERATE_ADDRESS)
	{
		// User wants a new DNP address so let's go and instruct the server to make us one
		char gen_id[DNP_ID_SIZE];
		err = dnp_kernel_server_create_address(gen_id);
		if (err < 0)
		{
			printk(KERN_ERR "%s failed to create DNP address, err=%i\n", __FUNCTION__, err);
			goto out;
		}

		err = copy_to_user(dnp_address->addr, gen_id, DNP_ID_SIZE);
		if (err < 0)
		{
			printk(KERN_ERR "%s failed to copy generated DNP address to user space, err=%i\n", __FUNCTION__, err);
			goto out;
		}
		memcpy(addr, gen_id, sizeof(gen_id));
	}

	__u16 port = dnp_address->port;
	mutex_lock(&port_list_mutex);
	err = dnp_set_port(&root_port_list, port, sock);
	mutex_unlock(&port_list_mutex);
	if (err < 0)
	{
		printk(KERN_ERR "%s Failed to set port err=%i\n", __FUNCTION__, err);
		goto out;
	}

	// Great let's now set the binded address in this socket
	memcpy(dnp_dnpdatagramsock(sock)->addr, &addr, sizeof(addr));
	dnp_dnpdatagramsock(sock)->port = dnp_address->port;
out:
	return err;
}

static const struct proto_ops dnpdatagramsock_ops = {
	.family = DNP_FAMILY,
	.owner = THIS_MODULE,
	.release = dnpdatagramsock_release,
	.bind = dnpdatagramsock_bind,
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

	// Let's add the socket to the list
	mutex_lock(&sock_list_mutex);
	dnp_add_sock(&sock_list, sock);
	mutex_unlock(&sock_list_mutex);
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