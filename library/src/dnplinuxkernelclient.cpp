#include "dnplinuxkernelclient.h"
#include "dnpmodshared.h"
#include "dnpexception.h"
#include "network.h"
#include "system.h"
#include "crypto/rsa.h"
#include "dnpdatagrampacket.h"
#include "misc.h"
#include <memory.h>
#include <unistd.h>
#include <iostream>

using namespace Dnp;
DnpLinuxKernelClient::DnpLinuxKernelClient(System *system) : DnpKernelClient(system)
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

    set_socket_timeout(DNP_KERNEL_TIMEOUT_SECONDS);
}

DNP_LINUX_KERNEL_SEND_RES DnpLinuxKernelClient::send_packet(const struct dnp_kernel_packet &kernel_packet)
{
    char buf[NLMSG_SPACE(sizeof(struct dnp_kernel_packet))];
    memset(buf, 0, NLMSG_SPACE(sizeof(struct dnp_kernel_packet)));
    struct nlmsghdr *msghdr = (struct nlmsghdr *)buf;

    memset(msghdr, 0, NLMSG_SPACE(sizeof(struct dnp_kernel_packet)));
    msghdr->nlmsg_len = NLMSG_SPACE(sizeof(struct dnp_kernel_packet));
    msghdr->nlmsg_pid = getpid(); // self pid
    msghdr->nlmsg_flags = 0;

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

DNP_LINUX_KERNEL_RECV_RES DnpLinuxKernelClient::recv_packet(struct dnp_kernel_packet &kernel_packet)
{
    char buf[NLMSG_SPACE(sizeof(struct dnp_kernel_packet))];
    memset(buf, 0, NLMSG_SPACE(sizeof(struct dnp_kernel_packet)));
    struct nlmsghdr *msghdr = (struct nlmsghdr *)buf;
    memset(msghdr, 0, NLMSG_SPACE(sizeof(struct dnp_kernel_packet)));
    msghdr->nlmsg_len = NLMSG_SPACE(sizeof(struct dnp_kernel_packet));
    msghdr->nlmsg_pid = getpid(); // self pid
    msghdr->nlmsg_flags = 0;

    struct iovec iov;
    struct msghdr msg;
    memset(&msg, 0, sizeof(struct msghdr));
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)msghdr;
    iov.iov_len = msghdr->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    memset(&kernel_packet, 0, sizeof(kernel_packet));
    set_socket_timeout(3);
    if (recvmsg(sock, &msg, 0) < 0)
    {
        return DNP_LINUX_KERNEL_RECV_ERROR;
    }

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

void DnpLinuxKernelClient::init_packet(DNP_KERNEL_PACKET_TYPE type, struct dnp_kernel_packet &kernel_packet)
{
    memset(&kernel_packet, 0, sizeof(struct dnp_kernel_packet));
    kernel_packet.type = type;
    kernel_packet.sem_id = -1;
}

void DnpLinuxKernelClient::send_ping_packet()
{
    CREATE_KERNEL_PACKET(packet, DNP_KERNEL_PACKET_TYPE_HELLO)
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

void DnpLinuxKernelClient::create_dnp_id_then_respond(DNP_SEMAPHORE_ID sem_id)
{
    DnpFile *dnp_file = this->system->getDnpFile();
    struct rsa_keypair keypair = Rsa::generateKeypair();
    // Let's try and save this to disk and if its successful then we can return this packet
    dnp_file->addDnpAddress(keypair.pub_key_md5_hash, keypair.pub_key, keypair.private_key);

    CREATE_KERNEL_PACKET(packet, DNP_KERNEL_PACKET_TYPE_CREATE_ID_RESPONSE)
    packet.sem_id = sem_id;
    memcpy(packet.create_id_packet_res.created_id, keypair.pub_key_md5_hash.c_str(), DNP_ID_SIZE);

    if (send_packet(packet) != DNP_LINUX_KERNEL_SEND_OK)
        throw DnpException(DNP_EXCEPTION_KERNEL_CLIENT_PACKET_SEND_FAILURE, "Something went wrong sending the create id response to the kernel");
}

void DnpLinuxKernelClient::initNetworkDatagramPacketFromKernelPacket(struct Packet &net_packet, struct dnp_kernel_packet &kern_packet)
{
    if (net_packet.type != PACKET_TYPE_DATAGRAM)
        throw std::logic_error("Expecting a datagram packet");
}

void DnpLinuxKernelClient::send_datagram_then_respond_impl(struct dnp_kernel_packet &res_packet, struct dnp_kernel_packet &packet)
{
    if (packet.type != DNP_KERNEL_PACKET_TYPE_SEND_DATAGRAM)
    {
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "You passed in an illegal packet, we are expecting a DNP_KERNEL_PACKET_TYPE_SEND_DATAGRAM");
    }

    DnpFile *dnp_file = this->system->getDnpFile();
    struct dnp_address dnp_address;
    if (!dnp_file->getDnpAddress(std::string(packet.datagram_packet.send_from.address, DNP_ID_SIZE), &dnp_address))
    {
        res_packet.datagram_res_packet.res = DNP_KERNEL_SERVER_DATAGRAM_FAILED_ILLEGAL_ADDRESS;
        return;
    }

    std::string private_key = "";
    if (!dnp_file->readPrivateKey(&dnp_address, private_key))
    {
        throw DnpException(DNP_EXCEPTION_PRIVATE_KEY_FAILURE, "Problem finding private key for sender, are you allowed to send as this id");
    }

    std::string public_key = "";
    if (!dnp_file->readPublicKey(&dnp_address, public_key))
    {
        throw DnpException(DNP_EXCEPTION_PRIVATE_KEY_FAILURE, "Problem finding public key for sender, this may indicate corruption in the DNP file");
    }

    // send the packet to the decentralized network

    std::unique_ptr<DnpDatagramPacket> datagram = this->system->getNetwork()->newPacket<DnpDatagramPacket>();
    datagram->setToAddress(std::string(packet.datagram_packet.send_to.address, sizeof(packet.datagram_packet.send_to.address)),
                           packet.datagram_packet.send_to.port);
    datagram->setFromAddress(std::string(packet.datagram_packet.send_from.address, sizeof(packet.datagram_packet.send_from.address)),
                           packet.datagram_packet.send_from.port);

    datagram->setData(packet.datagram_packet.buf, sizeof(packet.datagram_packet.buf));
    datagram->setPrivateKey(private_key);
    datagram->setPublicKey(public_key);

    std::cout << "Broadcasting datagram packet" << std::endl;
    datagram->broadcast();

}

void DnpLinuxKernelClient::send_datagram_then_respond(struct dnp_kernel_packet packet)
{
    CREATE_KERNEL_PACKET(res_packet, DNP_KERNEL_PACKET_TYPE_SEND_DATAGRAM_RESPONSE)
    res_packet.datagram_res_packet.res = DNP_KERNEL_SERVER_DATAGRAM_OK;
    res_packet.sem_id = packet.sem_id;
    try
    {
        send_datagram_then_respond_impl(res_packet, packet);
    }
    catch (std::logic_error &ex)
    {
        res_packet.datagram_res_packet.res = DNP_KERNEL_SERVER_DATAGRAM_FAILED_UNKNOWN;
        std::cout << ex.what() << std::endl;
    }

    if (send_packet(res_packet) != DNP_LINUX_KERNEL_SEND_OK)
    {
        throw DnpException(DNP_EXCEPTION_KERNEL_CLIENT_PACKET_SEND_FAILURE, "Failed to send datagram response back to the kernel");
    }
}

void DnpLinuxKernelClient::sendPacketToKernel(struct dnp_kernel_packet &packet)
{
    send_packet(packet);
}

void DnpLinuxKernelClient::run()
{
    Dnp::ThreadPool *thread_pool = system->getThreadPool();
    while (1)
    {
        try
        {
            struct dnp_kernel_packet packet;
            recv_packet(packet);
            switch (packet.type)
            {
            case DNP_KERNEL_PACKET_TYPE_CREATE_ID:
                create_dnp_id_then_respond(packet.sem_id);
                //thread_pool->addTask(std::bind(&DnpLinuxKernelClient::create_dnp_id_then_respond, this, packet.sem_id));
                break;

            case DNP_KERNEL_PACKET_TYPE_SEND_DATAGRAM:
                send_datagram_then_respond(packet);
                //thread_pool->addTask(std::bind(&DnpLinuxKernelClient::send_datagram_then_respond, this, packet));
                break;
            }
        }
        catch (Dnp::DnpException &ex)
        {
            std::cerr << ex.what() << std::endl;
        }

        usleep(50);
    }
}
