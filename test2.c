#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#define PORT 8080
#define MAXLINE 1024
#define DNP_FAMILY 43
#define DNP_DATAGRAM_PROTOCOL 0
#define DNP_MAX_PROTOCOLS 1
#define DNP_MAX_OPTIONS 4

#define NETLINK_DNP 31


#define SOCKET_OPTION_VALUE_INTEGER 0
#define SOCKET_OPTION_VALUE_BUFFER 1
typedef int DNP_SOCKET_OPTION_VALUE_TYPE;

#define DNP_SOCKET_OPTION_MUST_DELIVER 0
#define DNP_SOCKET_MUST_DELIVER 1
#define DNP_SOCKET_NO_DELIVERY_ACCEPTABLE 0

int main()
{
    struct sockaddr_nl src_addr, dest_addr;
    struct iovec iov;
    struct msghdr msg;
    struct nlmsghdr* requestSockNlh;
    char msgOut[500];
    int requestSockFd = socket(PF_NETLINK, SOCK_RAW, NETLINK_DNP);
    
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = 0; //we do not use getpid() in order to let kernel set unique ID and we will not intercept with other our calls

    if (bind(requestSockFd, (struct sockaddr *)&src_addr, sizeof(src_addr)) != 0)
    {
        printf("unable to bind\n");
        requestSockFd = -1;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;    // For Linux Kernel
    dest_addr.nl_groups = 0; // unicast

    requestSockNlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(1000));
    if (!requestSockNlh)
    {
        close(requestSockFd);
        requestSockFd = -1;
        return -1;
    }

    memset(requestSockNlh, 0, NLMSG_SPACE(1000));
    requestSockNlh->nlmsg_len = NLMSG_SPACE(1000);
    requestSockNlh->nlmsg_pid = getpid(); // self pid
    requestSockNlh->nlmsg_flags = 0;

    memcpy(NLMSG_DATA(requestSockNlh), &msgOut, sizeof(msgOut));

    iov.iov_base = (void *)requestSockNlh;
    iov.iov_len = requestSockNlh->nlmsg_len;

    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg(requestSockFd, &msg, 0);

    return 0;
}