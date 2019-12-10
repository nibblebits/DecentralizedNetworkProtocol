
#include "dnpkernelserver.h"
#include "dnp.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/delay.h>

struct sock *nl_sk = NULL;
__u32 pid = -1;
DEFINE_MUTEX(pid_lock);

/**
 * Upon receving a packet from the kernel the send_and_waits array will up the semaphore that is provided in the kernel packet
 * this is used to allow the kernel to wait for packet responses when it sends packet
 */
struct send_and_wait
{
    struct semaphore sem;
    struct dnp_kernel_packet packet;
    bool taken;
    struct sock *sk;
};

static struct send_and_wait send_and_waits[DNP_TOTAL_SEND_AND_WAITS];
DEFINE_MUTEX(send_and_wait_lock);

void dnp_kernel_server_new_packet(DNP_KERNEL_PACKET_TYPE type, struct dnp_kernel_packet *packet)
{
    memset(packet, 0, sizeof(struct dnp_kernel_packet));
    packet->type = type;
}

int dnp_kernel_server_send_packet_to_pid(struct dnp_kernel_packet *packet, __u32 _pid)
{
    int res = -1;
    int msg_size = sizeof(struct dnp_kernel_packet);

    struct sk_buff *skb_out = nlmsg_new(msg_size, 0);
    struct nlmsghdr *nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    memcpy(nlmsg_data(nlh), packet, msg_size);
    res = nlmsg_unicast(nl_sk, skb_out, _pid);

    printk(KERN_INFO "Sending packet, res=%i\n", res);
    return res;
}

int dnp_kernel_server_send_packet(struct dnp_kernel_packet *packet)
{
    return dnp_kernel_server_send_packet_to_pid(packet, pid);
}

int dnp_kernel_server_create_address(char *gen_id_buf, struct sock *sk)
{
    ENSURE_KERNEL_BINDED
    int res = 0;

    NEW_DNP_KERNEL_PACKET(res_packet, -1)
    NEW_DNP_KERNEL_PACKET(packet, DNP_KERNEL_PACKET_TYPE_CREATE_ID)
    res = dnp_kernel_server_send_and_wait(packet, res_packet, sk);
    if (res < 0)
    {
        printk(KERN_ERR "%s failed to send packet to kernel server has it crashed?\n", __FUNCTION__);
        goto out;
    }

    memcpy(gen_id_buf, res_packet->create_id_packet_res.created_id, sizeof(res_packet->create_id_packet_res.created_id));

out:
    FREE_DNP_KERNEL_PACKET(packet)
    FREE_DNP_KERNEL_PACKET(res_packet)

    return res;
}

DNP_KERNEL_SERVER_PID_RES dnp_kernel_server_set_pid(__u32 _pid)
{
    DNP_KERNEL_SERVER_PID_RES ret = DNP_KERNEL_SERVER_PID_OK;
    mutex_lock(&pid_lock);
    if (pid != -1)
    {
        printk(KERN_ERR "%s Failed to set pid as pid is already set\n", __FUNCTION__);
        ret = DNP_KERNEL_SERVER_PID_ALREADY_SET;
        goto out;
    }
    pid = _pid;

out:
    mutex_unlock(&pid_lock);
    return ret;
}

DNP_HELLO_RESPONSE dnp_kernel_server_get_hello_response_for_pid_res(DNP_KERNEL_SERVER_PID_RES res)
{
    DNP_HELLO_RESPONSE hello_res = DNP_HELLO_RESPONSE_OK;
    switch (res)
    {
    case DNP_KERNEL_SERVER_PID_ALREADY_SET:
        hello_res = DNP_HELLO_RESPONSE_PID_ALREADY_SET;
        break;
    };

    return hello_res;
}

void dnp_kernel_server_handle_hello_packet(struct nlmsghdr *nlh, struct dnp_kernel_packet *packet)
{
    printk(KERN_INFO "%s hello enter\n", __FUNCTION__);
    NEW_DNP_KERNEL_PACKET(res_packet, DNP_KERNEL_PACKET_TYPE_HELLO_RESPONSE)
    DNP_HELLO_RESPONSE hello_res = DNP_HELLO_RESPONSE_OK;
    DNP_KERNEL_SERVER_PID_RES res = dnp_kernel_server_set_pid(nlh->nlmsg_pid);
    hello_res = dnp_kernel_server_get_hello_response_for_pid_res(res);
    res_packet->hello_res_packet.res = hello_res;
    dnp_kernel_server_send_packet_to_pid(res_packet, nlh->nlmsg_pid);
    FREE_DNP_KERNEL_PACKET(res_packet)
}

DNP_SEMAPHORE_ID dnp_kernel_server_create_send_and_wait(struct sock *sk)
{
    DNP_SEMAPHORE_ID res = -ENOMEM;
    // Create a send and wait
    mutex_lock(&send_and_wait_lock);
    for (int i = 0; i < DNP_TOTAL_SEND_AND_WAITS; i++)
    {
        struct send_and_wait *saw = &send_and_waits[i];
        if (!saw->taken)
        {
            saw->taken = true;
            saw->sk = sk;
            res = i;
            goto out;
        }
    }
out:
    mutex_unlock(&send_and_wait_lock);
    return res;
}

void dnp_kernel_server_send_and_wait_copy_free(struct dnp_kernel_packet *dst, int sem_id)
{
    mutex_lock(&send_and_wait_lock);
    memcpy(dst, &send_and_waits[sem_id].packet, sizeof(send_and_waits[sem_id].packet));
    send_and_waits[sem_id].taken = false;
    mutex_unlock(&send_and_wait_lock);
}

void dnp_kernel_server_up_send_and_waits_for_socket(struct sock *sk)
{
    mutex_lock(&send_and_wait_lock);
    for (int i = 0; i < DNP_TOTAL_SEND_AND_WAITS; i++)
    {
        struct send_and_wait* saw = (struct send_and_wait*) &send_and_waits[i];
        if (saw->taken && saw->sk == sk)
        {
            // Let's up the semaphore
            up(&saw->sem);
            saw->taken = false;
        }
    }
    mutex_unlock(&send_and_wait_lock);
}

int dnp_kernel_server_send_and_wait(struct dnp_kernel_packet *packet, struct dnp_kernel_packet *res_packet, struct sock *sk)
{
    memset(res_packet, 0, sizeof(struct dnp_kernel_packet));
    res_packet->type = -1;

    int res = 0;
    // Create a send and wait for us
    DNP_SEMAPHORE_ID sem_id = dnp_kernel_server_create_send_and_wait(sk);
    if (sem_id < 0)
    {
        res = sem_id;
        goto out;
    }

    // Attach the semaphore id so that when we get a packet back we know :)
    packet->sem_id = sem_id;

    // Send the packet
    res = dnp_kernel_server_send_packet(packet);
    if (res < 0)
    {
        goto out;
    }

    // Wait for a packet response
    res = down_timeout(&send_and_waits[sem_id].sem, 3000);
    if (res < 0)
    {
        printk("%s semaphore timed out\n", __FUNCTION__);
        goto out;
    }

    // Copy packet recieved to result and mark send and wait free
    dnp_kernel_server_send_and_wait_copy_free(res_packet, sem_id);

out:
    return res;
}

void dnp_kernel_server_up_send_and_wait(struct dnp_kernel_packet *packet)
{
    mutex_lock(&send_and_wait_lock);
    if (packet->sem_id >= DNP_TOTAL_SEND_AND_WAITS)
    {
        printk(KERN_ERR "%s provided packet sem_id=%i however this is out of bounds! Total allowed send and waits=%i\n", __FUNCTION__, packet->sem_id, DNP_TOTAL_SEND_AND_WAITS);
        goto out;
    }

    if (!send_and_waits[packet->sem_id].taken)
    {
        // Whats going on here? This send and wait is free!
        printk(KERN_ERR "%s attempted to up a free send and wait, this is not allowed!\n", __FUNCTION__);
        goto out;
    }

    memcpy(&send_and_waits[packet->sem_id].packet, packet, sizeof(struct dnp_kernel_packet));
    up(&send_and_waits[packet->sem_id].sem);

out:
    mutex_unlock(&send_and_wait_lock);
}

void dnp_kernel_server_handle_recv_datagram_packet(struct nlmsghdr *nlh, struct dnp_kernel_packet *packet)
{
    printk(KERN_INFO "%s Handling recieved datagram packet\n", __FUNCTION__);
    const struct dnp_protocol *protocol = NULL;
    int res = dnp_get_protocol(DNP_DATAGRAM_PROTOCOL, &protocol);
    if (res < 0)
    {
        printk(KERN_ERR "%s Protocol %i could not be found\n", __FUNCTION__, res);
        return;
    }

    if (protocol->datagram_recv == NULL)
    {
        printk(KERN_ERR "%s Protocol datagram_recv not implemented\n", __FUNCTION__);
        return;
    }

    res = protocol->datagram_recv(packet);
    if (res < 0)
    {
        printk(KERN_ERR "%s Bad response %i\n", __FUNCTION__, res);
    }
}

void dnp_kernel_server_handle_packet(struct nlmsghdr *nlh, struct dnp_kernel_packet *packet)
{

    printk(KERN_INFO "%s enter\n", __FUNCTION__);

    switch (packet->type)
    {
    case DNP_KERNEL_PACKET_TYPE_HELLO:
    {
        dnp_kernel_server_handle_hello_packet(nlh, packet);
    }
    break;

    case DNP_KERNEL_PACKET_TYPE_CREATE_ID_RESPONSE:
        // Do nothing we handle this else where
        break;

    case DNP_KERNEL_PACKET_TYPE_SEND_DATAGRAM_RESPONSE:
        // Do nothing we handle this else where
        break;

    case DNP_KERNEL_PACKET_TYPE_RECV_DATAGRAM:
        dnp_kernel_server_handle_recv_datagram_packet(nlh, packet);
        break;

    default:
        printk(KERN_INFO "%s unrecognized kernel packet: %i\n", __FUNCTION__, packet->type);
    }

    // Semaphore is present in packet, we must up it
    if (packet->sem_id != -1)
    {
        dnp_kernel_server_up_send_and_wait(packet);
    }
}

void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct dnp_kernel_packet *packet;

    printk(KERN_INFO "%s enter\n", __FUNCTION__);

    nlh = (struct nlmsghdr *)skb->data;
    if (nlh->nlmsg_len < sizeof(struct dnp_kernel_packet))
    {
        printk(KERN_INFO "%s: nlmsg_len=%d\n", __FUNCTION__, nlh->nlmsg_len);
        return;
    }

    packet = (struct dnp_kernel_packet *)nlmsg_data(nlh);
    dnp_kernel_server_handle_packet(nlh, packet);
}

bool dnp_kernel_server_binded_to_pid(void)
{
    bool binded = false;
    mutex_lock(&pid_lock);
    binded = pid != -1;
    mutex_unlock(&pid_lock);
    return binded;
}

void dnp_kernel_server_init_send_and_waits(void)
{
    memset(&send_and_waits, 0, sizeof(send_and_waits));
    for (int i = 0; i < DNP_TOTAL_SEND_AND_WAITS; i++)
    {
        sema_init(&send_and_waits[i].sem, 0);
    }
}

void dnp_kernel_server_init(void)
{
    // Initialize all of the send and waits
    dnp_kernel_server_init_send_and_waits();

    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_DNP, &cfg);
    if (!nl_sk)
    {
        printk(KERN_ERR "Error creating interface.\n");
    }
}

void dnp_kernel_server_exit(void)
{
    if (nl_sk)
    {
        printk(KERN_INFO "%s Releasing socket\n", __FUNCTION__);
        netlink_kernel_release(nl_sk);
    }
}