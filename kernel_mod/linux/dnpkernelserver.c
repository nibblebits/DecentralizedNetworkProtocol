
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

void dnp_kernel_server_new_packet(DNP_KERNEL_PACKET_TYPE type, struct dnp_kernel_packet* packet)
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

void dnp_kernel_server_handle_hello_packet(struct nlmsghdr* nlh, struct dnp_kernel_packet *packet)
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

void dnp_kernel_server_handle_packet(struct nlmsghdr* nlh, struct dnp_kernel_packet *packet)
{

    printk(KERN_INFO "%s enter\n", __FUNCTION__);


    switch (packet->type)
    {
    case DNP_KERNEL_PACKET_TYPE_HELLO:
    {
        dnp_kernel_server_handle_hello_packet(nlh, packet);
    }
    break;

    default:
        printk(KERN_INFO "%s unrecognized kernel packet: %i\n", __FUNCTION__, packet->type);
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

void dnp_kernel_server_init(void)
{
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