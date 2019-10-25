#include "dnplinuxkernelclient.h"
#include "dnpmodshared.h"
#include "dnpexception.h"
#include <memory.h>
#include <unistd.h>
#include <iostream>

using namespace Dnp;
DnpLinuxKernelClient::DnpLinuxKernelClient() : DnpKernelClient()
{
    sock = -1;
}

DnpLinuxKernelClient::~DnpLinuxKernelClient()
{
}

void DnpLinuxKernelClient::bind_socket()
{
    struct sockaddr_nl src_addr;

    sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_DNP);

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = 0;

    if (bind(sock, (struct sockaddr *)&src_addr, sizeof(src_addr)) != 0)
    {
        throw DnpException(DNP_EXCEPTION_KERNEL_CLIENT_BIND_FAILURE, "Failed to bind to kernel netlink");
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;    // For Linux Kernel
    dest_addr.nl_groups = 0; // unicast

    msghdr = (struct nlmsghdr*) new char[NLMSG_SPACE(sizeof(struct dnp_kernel_packet))];
    if (!msghdr)
    {
        close(sock);
        sock = -1;
        return;
    }

    memset(msghdr, 0, NLMSG_SPACE(sizeof(struct dnp_kernel_packet)));
    msghdr->nlmsg_len = NLMSG_SPACE(sizeof(struct dnp_kernel_packet));
    msghdr->nlmsg_pid = getpid(); // self pid
    msghdr->nlmsg_flags = 0;
}

DNP_LINUX_KERNEL_SEND_RES DnpLinuxKernelClient::send_packet(const struct dnp_kernel_packet &kernel_packet)
{
    struct iovec iov;
    struct msghdr msg;
    memcpy(NLMSG_DATA(msghdr), &kernel_packet, sizeof(kernel_packet));

    iov.iov_base = (void *)msghdr;
    iov.iov_len = msghdr->nlmsg_len;

    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(sock, &msg, 0) < 0)
        return DNP_LINUX_KERNEL_SEND_ERROR;

    return DNP_LINUX_KERNEL_SEND_OK;
}

void DnpLinuxKernelClient::set_socket_timeout(int seconds)
{
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(struct timeval));
}

DNP_LINUX_KERNEL_RECV_RES DnpLinuxKernelClient::recv_packet(struct dnp_kernel_packet &kernel_packet, int timeout = 5)
{
    struct iovec iov;
    struct msghdr msg;

    iov.iov_base = (void *)msghdr;
    iov.iov_len = msghdr->nlmsg_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    set_socket_timeout(timeout);
    if (recvmsg(sock, &msg, 0) < 0)
    {
        return DNP_LINUX_KERNEL_RECV_ERROR;
    }

    memset(&kernel_packet, 0, sizeof(kernel_packet));
    memcpy(&kernel_packet, NLMSG_DATA(msghdr), sizeof(kernel_packet));
    return DNP_LINUX_KERNEL_RECV_OK;
}

void DnpLinuxKernelClient::recv_ping_response()
{
    struct dnp_kernel_packet packet;
    if (recv_packet(packet) != DNP_LINUX_KERNEL_RECV_OK)
    {
        throw DnpException(DNP_EXCEPTION_KERNEL_CLIENT_HELLO_FAILURE, "Hello failed because we failed to recieve a packet from the kernel. Is the module loaded?");
    }
    if (packet.type != DNP_KERNEL_PACKET_TYPE_HELLO_RESPONSE)
    {
        throw DnpException(DNP_EXCEPTION_KERNEL_CLIENT_UNEXPECTED_PACKET_RESPONSE);
    }

    if (packet.hello_res_packet.res != DNP_HELLO_RESPONSE_OK)
    {
        std::string fail_message = "";
        switch (packet.hello_res_packet.res)
        {
        case DNP_HELLO_RESPONSE_PID_ALREADY_SET:
            fail_message = "Hello failed because the kernel module is already binded to a PID. Did you run twice?";
            break;

        default:
            fail_message = "Failure unknown, res=" + std::to_string(packet.hello_res_packet.res);
            break;
        }
        throw DnpException(DNP_EXCEPTION_KERNEL_CLIENT_HELLO_FAILURE, fail_message);
    }
}

void DnpLinuxKernelClient::send_ping_packet()
{
    struct dnp_kernel_packet packet;
    packet.type = DNP_KERNEL_PACKET_TYPE_HELLO;
    if (send_packet(packet) != DNP_LINUX_KERNEL_SEND_OK)
        throw DnpException(DNP_EXCEPTION_KERNEL_CLIENT_HELLO_FAILURE, "Failed to send inital PING packet!");

    // Now recieve and handle the response
    recv_ping_response();
}

void DnpLinuxKernelClient::start()
{
    bind_socket();
    send_ping_packet();

    // Start base client
    DnpKernelClient::start();
}

void DnpLinuxKernelClient::run()
{
    return;
    while (1)
    {
        try
        {
            struct dnp_kernel_packet packet;
            recv_packet(packet);
            if (packet.type == DNP_KERNEL_PACKET_TYPE_DATAGRAM)
            {
                std::cout << packet.datagram_packet.buf << std::endl;
            }
        }
        catch (Dnp::DnpException &ex)
        {
            std::cerr << ex.what() << std::endl;
        }

        usleep(50);
    }
}
