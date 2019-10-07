
/** 
 * @file    hello.c 
 * @author  Akshat Sinha 
 * @date    10 Sept 2016 
 * @version 0.1 
 * @brief  An introductory "Hello World!" loadable kernel 
 *  module (LKM) that can display a message in the /var/log/kern.log 
 *  file when the module is loaded and removed. The module can accept 
 *  an argument when it is loaded -- the name, which appears in the 
 *  kernel log files. 
*/
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h>   /* Needed for the macros */
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/memblock.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/bpf-cgroup.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/ip_tunnels.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <trace/events/udp.h>
#include <linux/static_key.h>
#include <trace/events/skb.h>
#include <net/busy_poll.h>
#include <net/sock_reuseport.h>
#include <net/addrconf.h>
#include <net/udp_tunnel.h>




///< The license type -- this affects runtime behavior
MODULE_LICENSE("GPL");

///< The author -- visible when you use modinfo
MODULE_AUTHOR("Daniel McCarthy");

///< The description -- see modinfo
MODULE_DESCRIPTION("DNP Network Module");

///< The version of the module
MODULE_VERSION("0.1");

atomic_long_t dnp_memory_allocated;

struct dnp_table dnp_table __read_mostly;

long sysctl_dnp_mem[3] __read_mostly;

int sysctl_dnp_rmem_min __read_mostly;

int sysctl_dnp_wmem_min __read_mostly;

int dnp_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    return -EINVAL;
}


int __dnp_disconnect(struct sock *sk, int flags)
{
    struct inet_sock *inet = inet_sk(sk);
    /*
	 *	1003.1g - break association.
	 */

    sk->sk_state = TCP_CLOSE;
    inet->inet_daddr = 0;
    inet->inet_dport = 0;
    sock_rps_reset_rxhash(sk);
    sk->sk_bound_dev_if = 0;
    if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
        inet_reset_saddr(sk);

    if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK))
    {
        sk->sk_prot->unhash(sk);
        inet->inet_sport = 0;
    }
    sk_dst_reset(sk);
    return 0;
}

int dnp_disconnect(struct sock *sk, int flags)
{
    lock_sock(sk);
    __dnp_disconnect(sk, flags);
    release_sock(sk);
    return 0;
}


/*
 *	IOCTL requests applicable to the UDP protocol
 */

int dnp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
    return -ENOIOCTLCMD;
}


int dnp_init_sock(struct sock *sk)
{
    return -1;
}


void dnp_destroy_sock(struct sock *sk)
{
    // Nothing for now
}

int dnp_setsockopt(struct sock *sk, int level, int optname,
                   char __user *optval, unsigned int optlen)
{
    return ip_setsockopt(sk, level, optname, optval, optlen);
}

int dnp_getsockopt(struct sock *sk, int level, int optname,
                   char __user *optval, int __user *optlen)
{
    return ip_getsockopt(sk, level, optname, optval, optlen);
}

int dnp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
    return -1;
}

EXPORT_SYMBOL(dnp_sendmsg);

int dnp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
                int flags, int *addr_len)
{
    return -1;
}

EXPORT_SYMBOL(dnp_recvmsg);

int dnp_sendpage(struct sock *sk, struct page *page, int offset,
                 size_t size, int flags)
{
    return -1;
}

void dnp_v4_rehash(struct sock *sk)
{
}

int dnp_v4_get_port(struct sock *sk, unsigned short snum)
{
    return -1;
}

int dnp_abort(struct sock *sk, int err)
{
    return -1;
}


static struct sock *dnp_get_idx(struct seq_file *seq, loff_t pos)
{
	return NULL;
}

void *dnp_seq_start(struct seq_file *seq, loff_t *pos)
{
	return NULL;
}

void *dnp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return NULL;
}

void dnp_seq_stop(struct seq_file *seq, void *v)
{
	return NULL;
}


int dnp_seq_show(struct seq_file *seq, void *v)
{
	return 0;
}


/**
 *	struct udp_hslot - UDP hash slot
 *
 *	@head:	head of list of sockets
 *	@count:	number of sockets in 'head' list
 *	@lock:	spinlock protecting changes to head/count
 */
struct dnp_hslot {
	struct hlist_head	head;
	int			count;
	spinlock_t		lock;
} __attribute__((aligned(2 * sizeof(long))));

/**
 *	struct udp_table - UDP table
 *
 *	@hash:	hash table, sockets are hashed on (local port)
 *	@hash2:	hash table, sockets are hashed on (local port, local address)
 *	@mask:	number of slots in hash tables, minus 1
 *	@log:	log2(number of slots in hash table)
 */
struct dnp_table {
	struct dnp_hslot	*hash;
	struct dnp_hslot	*hash2;
	unsigned int		mask;
	unsigned int		log;
};

struct proto dnp_prot = {
    .name = "DNP",
    .owner = THIS_MODULE,
    .close = udp_lib_close,
    .connect = ip4_datagram_connect,
    .disconnect = dnp_disconnect,
    .ioctl = dnp_ioctl,
    .init = dnp_init_sock,
    .destroy = dnp_destroy_sock,
    .setsockopt = dnp_setsockopt,
    .getsockopt = dnp_getsockopt,
    .sendmsg = dnp_sendmsg,
    .recvmsg = dnp_recvmsg,
    .sendpage = dnp_sendpage,
    .release_cb = ip4_datagram_release_cb,
    .hash = udp_lib_hash,
    .unhash = udp_lib_unhash,
    .rehash = dnp_v4_rehash,
    .get_port = dnp_v4_get_port,
    .memory_allocated = &dnp_memory_allocated,
    .sysctl_mem = sysctl_dnp_mem,
	.sysctl_wmem	   = &sysctl_udp_wmem_min,
	.sysctl_rmem	   = &sysctl_udp_rmem_min,
    .obj_size = sizeof(struct udp_sock),
    .h.udp_table = &udp_table,
    .diag_destroy = dnp_abort,
};
EXPORT_SYMBOL(dnp_prot);


int dnp_seq_open(struct inode *inode, struct file *file)
{
	return -1;
}
EXPORT_SYMBOL(dnp_seq_open);


static const struct file_operations dnp_afinfo_seq_fops = {
	.owner    = THIS_MODULE,
	.open     = dnp_seq_open,
	.read     = seq_read,
	.llseek   = seq_lseek,
	.release  = seq_release_net
};



struct dnp_seq_afinfo {
	char				*name;
	sa_family_t			family;
	struct dnp_table		*dnp_table;
	const struct file_operations	*seq_fops;
	struct seq_operations		seq_ops;
};


static struct dnp_seq_afinfo dnp_seq_afinfo = {
	.name		= "dnp",
	.family		= AF_INET,
	.dnp_table	= &dnp_table,
	.seq_fops	= &dnp_afinfo_seq_fops,
	.seq_ops	= {
		.show		= dnp_seq_show,
	},
};

void *udp_seq_start(struct seq_file *seq, loff_t *pos)
{
	return NULL;
}
EXPORT_SYMBOL(udp_seq_start);



static int __net_init dnp_proc_init_net(struct net *net)
{
    if(!proc_create_data("dnp", S_IRUGO, net->proc_net,
			      dnp_seq_afinfo.seq_fops, &dnp_seq_afinfo))
        return -ENOMEM;

    return 0;
}


static void __net_exit dnp_proc_exit_net(struct net *net)
{
	remove_proc_entry(dnp_seq_afinfo.name, net->proc_net);
}

static struct pernet_operations dnp_net_ops = {
    .init = dnp_proc_init_net,
    .exit = dnp_proc_exit_net,
};


const struct seq_operations dnp_seq_ops = {
	.start		= dnp_seq_start,
	.next		= dnp_seq_next,
	.stop		= dnp_seq_stop,
	.show		= dnp_seq_show,
};
EXPORT_SYMBOL(dnp_seq_ops);



static int __init dnp_start(void)
{
    printk(KERN_INFO "Loading DNP module...\n");
    return register_pernet_subsys(&dnp_net_ops);
}

static void __exit dnp_end(void)
{
    printk(KERN_INFO "Unloading DNP module.\n");
}

module_init(dnp_start);
module_exit(dnp_end);
