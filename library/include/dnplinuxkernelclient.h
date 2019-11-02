#ifndef DNPLINUXKERNELCLIENT_H
#define DNPLINUXKERNELCLIENT_H
#include <thread>
#include <memory>
#include <queue>
#include <mutex>

#include <sys/socket.h>
#include <linux/netlink.h>
#include "dnpkernelclient.h"
#include "dnpmodshared.h"

#define DNP_LINUX_KERNEL_RECV_OK 0
#define DNP_LINUX_KERNEL_RECV_ERROR 1
typedef int DNP_LINUX_KERNEL_RECV_RES;

#define DNP_LINUX_KERNEL_SEND_OK 0
#define DNP_LINUX_KERNEL_SEND_ERROR 1
typedef int DNP_LINUX_KERNEL_SEND_RES;

#define DNP_KERNEL_TIMEOUT_SECONDS 5

#define CREATE_KERNEL_PACKET(name, type) struct dnp_kernel_packet name; init_packet(type, name);
namespace Dnp
{
class System;
class DnpLinuxKernelClient : public DnpKernelClient
{
public:
    DnpLinuxKernelClient(System *system);
    virtual ~DnpLinuxKernelClient();

    virtual void start();
    virtual void run();

protected:
    void init_packet(DNP_KERNEL_PACKET_TYPE type, struct dnp_kernel_packet& kernel_packet);
    virtual DNP_LINUX_KERNEL_SEND_RES send_packet(const struct dnp_kernel_packet &kernel_packet);
    virtual DNP_LINUX_KERNEL_RECV_RES recv_packet(struct dnp_kernel_packet &kernel_packet);
    virtual void send_ping_packet();
    virtual void recv_ping_response();
    void send_create_id_res_packet(DNP_SEMAPHORE_ID sem_id);

private:
    void set_socket_timeout(int seconds);
    void bind_socket();

    int sock;
    struct sockaddr_nl dest_addr;
    struct sockaddr_nl src_addr;
};
}; // namespace Dnp
#endif