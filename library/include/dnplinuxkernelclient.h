#ifndef DNPLINUXKERNELCLIENT_H
#define DNPLINUXKERNELCLIENT_H
#include <thread>
#include <memory>
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

namespace Dnp
{
class DnpLinuxKernelClient : public DnpKernelClient
{
public:
    DnpLinuxKernelClient();
    virtual ~DnpLinuxKernelClient();

    virtual void start();
    virtual void run();

protected:
    virtual DNP_LINUX_KERNEL_SEND_RES send_packet(const struct dnp_kernel_packet &kernel_packet);
    virtual DNP_LINUX_KERNEL_RECV_RES recv_packet(struct dnp_kernel_packet &kernel_packet, int timeout);
    virtual void send_ping_packet();
    virtual void recv_ping_response();

private:
    void set_socket_timeout(int seconds);
    void bind_socket();

    int sock;

    struct sockaddr_nl dest_addr;
    struct sockaddr_nl src_addr;
    struct std::unique_ptr<nlmsghdr> msghdr;
};
}; // namespace Dnp
#endif