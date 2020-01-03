#include "dnp.h"
#include "dnpmodshared.h"
#include <net/sock.h>

LIST_HEAD(root_port_list);
DEFINE_MUTEX(port_list_mutex);

LIST_HEAD(sock_list);
DEFINE_MUTEX(sock_list_mutex);


static int dnpdatagramsock_is_binded(struct socket* sock)
{
	struct dnp_dnpdatagramsock* datagram_sock = dnp_dnpdatagramsock(sock->sk);
	if (datagram_sock->port != 0)
		return 0;

	return -EIO;
}

/**
 * Clones the provided packet and then adds it to the packet queue for this socket
 */
static int dnpdatagramsock_push_packet(struct socket *sock, struct dnp_kernel_packet *packet)
{
	struct dnp_dnpdatagramsock *datagram_sock = dnp_dnpdatagramsock(sock->sk);
	struct dnp_packet_queue_element *element = (struct dnp_packet_queue_element *)kzalloc(sizeof(struct dnp_socket), GFP_USER);
	// Packet must be copied as otherwise data will be lost
	element->packet = kzalloc(sizeof(struct dnp_kernel_packet), GFP_USER);
	memcpy(element->packet, packet, sizeof(struct dnp_kernel_packet));
	mutex_lock(&datagram_sock->packet_queue_mutex);
	list_add(&element->list, &datagram_sock->packet_queue);
	mutex_unlock(&datagram_sock->packet_queue_mutex);

	// We must up the packet queue added semaphore so people waiting for packets are alerted
	up(&datagram_sock->packet_queue_added_sem);

	return 0;
}

/**
 * Pops a packet from the packet queue for the provided socket, stores the packet in the packet provided.
 * Caller is responsible for freeing memory for this returned dnp_kernel_packet
 * however the dnp_packet_queue_element is freed upon calling this function
 */
static struct dnp_kernel_packet *dnpdatagramsock_pop_packet(struct socket *sock)
{
	struct dnp_kernel_packet *packet = NULL;
	struct dnp_dnpdatagramsock *datagram_sock = dnp_dnpdatagramsock(sock->sk);
	mutex_lock(&datagram_sock->packet_queue_mutex);

	if (list_empty(&datagram_sock->packet_queue))
	{
		printk(KERN_INFO "%s Nothing to pop\n", __FUNCTION__);
		goto out;
	}

	struct dnp_packet_queue_element *element = (struct dnp_packet_queue_element *)list_last_entry(&datagram_sock->packet_queue, struct dnp_packet_queue_element, list);
	if (!element)
	{
		goto out;
	}

	printk(KERN_INFO "%s element found %p\n", __FUNCTION__, element);
	packet = element->packet;

	// Let's pop it off
	list_del(&element->list);
	// Free the element
	kfree(element);

out:
	mutex_unlock(&datagram_sock->packet_queue_mutex);
	return packet;
}

/**
 * Waits until there is a packet in the packet queue and then returns zero on success.
 * If something went wrong or waiting failed then a non zero value is returned
 */
int dnpdatagramsock_wait_for_packet(struct socket *sock)
{
	int err = 0;
	int empty = 0;
	struct dnp_dnpdatagramsock *datagram_sock = dnp_dnpdatagramsock(sock->sk);
	mutex_lock(&datagram_sock->packet_queue_mutex);
	empty = list_empty(&datagram_sock->packet_queue);
	mutex_unlock(&datagram_sock->packet_queue_mutex);

	if (empty)
	{
		// The list is empty so we should wait until a packet arrives
		err = down_interruptible(&datagram_sock->packet_queue_added_sem);
		if (err < 0)
		{
			printk(KERN_ERR "%s waiting interrupted by user\n", __FUNCTION__);
			goto out;
		}
	}
	
out:
	return err;
}

void dnpdatagramsock_cleanup_packet_queue(struct socket *sock)
{
	struct dnp_dnpdatagramsock *datagram_sock = dnp_dnpdatagramsock(sock->sk);
	struct list_head *packet_queue_list_head = &datagram_sock->packet_queue;
	struct dnp_packet_queue_element *ptr = NULL;
	struct dnp_packet_queue_element *ptr_next = NULL;
	mutex_lock(&datagram_sock->packet_queue_mutex);

	printk(KERN_INFO "%s packet_queue_list_head=%p\n", __FUNCTION__, packet_queue_list_head);
	if (list_empty(packet_queue_list_head))
	{
		printk(KERN_INFO "%s packet queue is empty nothing to clean up\n", __FUNCTION__);
		goto out;
	}

	printk(KERN_INFO "%s List not empty\n", __FUNCTION__);

	list_for_each_entry_safe(ptr, ptr_next, packet_queue_list_head, list) 
	{
		printk(KERN_INFO "%s %p\n", __FUNCTION__, ptr);
		kfree(ptr->packet);
		list_del(&ptr->list);
		kfree(ptr);
	}

out:
	mutex_unlock(&datagram_sock->packet_queue_mutex);
}

static int dnpdatagramsock_cleanup_socket(struct socket *sock)
{
	printk(KERN_INFO "sock=%p\n", sock->sk);
	dnp_kernel_server_up_send_and_waits_for_socket(sock->sk);
	dnpdatagramsock_cleanup_packet_queue(sock);

	mutex_lock(&sock_list_mutex);
	dnp_remove_socket(&sock_list, sock);
	mutex_unlock(&sock_list_mutex);
	mutex_lock(&port_list_mutex);
	dnp_remove_port(&root_port_list, sock);
	mutex_unlock(&port_list_mutex);

	return 0;
}

static int dnpdatagramsock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	printk(KERN_INFO "%s", __FUNCTION__);
	if (!sk)
		return 0;

	dnpdatagramsock_cleanup_socket(sock);

	sock_orphan(sk);
	sock_put(sk);

	sock->sk = NULL;

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

	dnp_sock->options[optname].ival = val;
out:
	return rc;
}

int dnpdatagramsock_setsockopt(struct socket *sock, int level, int optname,
							   char __user *optval, unsigned int optlen)
{
	ENSURE_KERNEL_BINDED

	lock_sock(sock->sk);
	int rc = 0;

	struct dnp_dnpdatagramsock *dnp_sock = dnp_dnpdatagramsock(sock->sk);
	switch (optname)
	{
	case DNP_SOCKET_OPTION_MUST_DELIVER:
		dnpdatagramsock_set_integer_option_for_userspace(dnp_sock, optname, (int __user *)optval);
		break;
	};

	printk(KERN_INFO "dnpdatagramsock_setsockopt() complete\n");

	release_sock(sock->sk);
	return rc;
}

int dnpdatagramsock_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	ENSURE_KERNEL_BINDED
	ENSURE_SOCKET_BINDED_TO_PORT(sock)
	
	int err = 0;

	lock_sock(sock->sk);
	// Create our packets ready for later
	NEW_DNP_KERNEL_PACKET(res_packet, -1)
	NEW_DNP_KERNEL_PACKET(packet, DNP_KERNEL_PACKET_TYPE_SEND_DATAGRAM)

	if (!msg->msg_name)
	{
		printk(KERN_ERR "%s sending message without destination address is not allowed! msg_name is NULL\n", __FUNCTION__);
		err = -EDESTADDRREQ;
		goto out;
	}

	DECLARE_SOCKADDR(struct dnp_address *, dnp_address, msg->msg_name);
	if (dnp_address->addr == NULL)
	{
		printk(KERN_ERR "%s dnp_address->addr is NULL\n", __FUNCTION__);
		err = -EINVAL;
		goto out;
	}

	char send_to_addr[DNP_ID_SIZE];
	if (copy_from_user(send_to_addr, dnp_address->addr, sizeof(send_to_addr)) != 0)
	{
		printk(KERN_ERR "%s failed to copy data from user process\n", __FUNCTION__);
		err = -EINVAL;
		goto out;
	}

	printk("%s send_to_addr start=%x\n", __FUNCTION__, send_to_addr[0]);

	struct iovec *iov = (struct iovec *)msg->msg_iter.iov;
	memcpy(&packet->datagram_packet.buf, iov->iov_base, iov->iov_len);
	memcpy(packet->datagram_packet.send_from.address, dnp_dnpdatagramsock(sock->sk)->addr, sizeof(packet->datagram_packet.send_from.address));
	packet->datagram_packet.send_from.port = dnp_dnpdatagramsock(sock->sk)->port;
	memcpy(packet->datagram_packet.send_to.address, send_to_addr, sizeof(packet->datagram_packet.send_to.address));
	packet->datagram_packet.send_to.port = dnp_address->port;

	printk(KERN_INFO " port=%i\n", dnp_address->port);
	err = dnp_kernel_server_send_and_wait(packet, res_packet, sock->sk);
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
	release_sock(sock->sk);

	return err;
}

int dnpdatagramsock_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
							int flags)
{
	ENSURE_KERNEL_BINDED
	ENSURE_SOCKET_BINDED_TO_PORT(sock)

	lock_sock(sock->sk);
	int res = 0;
	printk(KERN_INFO "%s", __FUNCTION__);

	if (flags & DNP_WAIT)
	{
		dnpdatagramsock_wait_for_packet(sock);
	}

	struct dnp_kernel_packet *p = dnpdatagramsock_pop_packet(sock);
	if (!p)
	{
		printk(KERN_ERR "%s failed to pop packet from stack, maybe no packets waiting?\n", __FUNCTION__);
		res = -EIO;
		goto out;
	}

	struct dnp_kernel_packet_recv_datagram *datagram = (struct dnp_kernel_packet_recv_datagram *)&p->recv_datagram_packet;
	DECLARE_SOCKADDR(struct dnp_address_in *, dnp_out_address, msg->msg_name);

	if (len > sizeof(datagram->buf))
	{
		printk(KERN_ERR "%s requested size is bigger than datagram buffer size\n", __FUNCTION__);
		res = -EMSGSIZE;
		goto out;
	}

	memcpy(dnp_out_address->addr, &datagram->send_from.address, sizeof(datagram->send_from.address));
	dnp_out_address->port = datagram->send_from.port;
	msg->msg_namelen = sizeof(struct dnp_address_in);

	struct iovec *iov = (struct iovec *)msg->msg_iter.iov;
	memcpy(iov->iov_base, &datagram->buf, len);
	msg->msg_iter.count = 1;

	// Length is always size of buffer, but needs to be changed so its the length the user actually intended to send
	iov->iov_len = len;

out:
	if (p)
	{
		printk(KERN_INFO "%s p=%p freeing now\n", __FUNCTION__, p);
		kfree(p);
	}

	release_sock(sock->sk);
	return res;
}

int dnpdatagramsock_bind(struct socket *sock, struct sockaddr *saddr, int len)
{
	// Ensures the kernel is binded to the user host application that is running our DNP server (unrelated to this call)
	ENSURE_KERNEL_BINDED
	int err = 0;

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
		err = dnp_kernel_server_create_address(gen_id, sock->sk);
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

		printk(KERN_INFO "%s Generated address for bind\n", __FUNCTION__);
	}


	// Great let's now set the binded address in this socket
	memcpy(dnp_dnpdatagramsock(sock->sk)->addr, &addr, sizeof(addr));
	
	__u16 port = dnp_address->port;
	mutex_lock(&port_list_mutex);
	err = dnp_set_port(&root_port_list, port, sock);
	mutex_unlock(&port_list_mutex);
	if (err < 0)
	{
		printk(KERN_ERR "%s Failed to set port err=%i\n", __FUNCTION__, err);
		goto out;
	}

	dnp_dnpdatagramsock(sock->sk)->port = dnp_address->port;
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
	skb_queue_purge(&sk->sk_receive_queue);

	if (!sock_flag(sk, SOCK_DEAD))
	{
		pr_err("Freeing alive NFC raw socket %p\n", sk);
		return;
	}
}

static void dnpdatagramsock_init(struct dnp_dnpdatagramsock *sock)
{
	sock->port = 0;
	memset(sock->options, 0, sizeof(sock->options));
	mutex_init(&sock->packet_queue_mutex);
	sema_init(&sock->packet_queue_added_sem, 0);
	INIT_LIST_HEAD(&sock->packet_queue);
}

static int dnpdatagramsock_create(struct net *net, struct socket *sock,
								  const struct dnp_protocol *dnp_proto, int kern)
{
	struct sock *sk;

	printk(KERN_INFO "dnpdatagramsock_create()");

	printk(KERN_INFO "%s socket_list=%p\n", __FUNCTION__, &sock_list);


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
	if (dnp_add_sock(&sock_list, sock) < 0)
	{
		printk(KERN_ERR "Failed to add socket to list\n");
		goto out;
	}
out:
	mutex_unlock(&sock_list_mutex);
	return 0;
}

static int dnpdatagramsock_recv(struct dnp_kernel_packet *packet)
{
	printk(KERN_INFO "%s packet processing\n", __FUNCTION__);
	printk(KERN_INFO "%s socket_list=%p\n", __FUNCTION__, &sock_list);
	struct dnp_socket *dnp_sock = NULL;
	mutex_lock(&sock_list_mutex);
	dnp_sock = dnp_get_socket_by_address(&sock_list, &packet->recv_datagram_packet.send_to);
	mutex_unlock(&sock_list_mutex);
	if (!dnp_sock)
	{
		char id[DNP_ID_SIZE + 1];
		memcpy(id, &packet->recv_datagram_packet.send_to.address, DNP_ID_SIZE);
		id[DNP_ID_SIZE] = 0;

		printk(KERN_ERR "%s socket could not be located, it must not be binded address=%s\n", __FUNCTION__, id);
		return -EIO;
	}

	// Let's push the packet to the socket data
	dnpdatagramsock_push_packet(dnp_sock->sock, packet);

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
	.create = dnpdatagramsock_create,
	.datagram_recv = dnpdatagramsock_recv,
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