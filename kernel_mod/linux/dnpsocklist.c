#include "dnp.h"

bool dnp_has_sock(struct list_head *list, struct socket *socket)
{
    struct dnp_socket *ptr = NULL;
    list_for_each_entry(ptr, list, list)
    {
        if (ptr->sock == socket)
            return true;
    }

    return false;
}

struct dnp_socket* dnp_get_socket_by_address(struct list_head* list, struct dnp_kernel_address* addr)
{
    struct dnp_socket* ptr = NULL;
    list_for_each_entry(ptr, list, list)
    {
        struct socket* sock = ptr->sock;
        struct dnp_dnpdatagramsock* datagram_sock = dnp_dnpdatagramsock(sock->sk);
        if(memcmp(datagram_sock->addr, addr->address, sizeof(datagram_sock->addr)) == 0 && datagram_sock->port == addr->port)
        {
            return ptr;
        }
    }

    return NULL;
}

struct dnp_socket *dnp_get_dnp_socket_by_socket(struct list_head *list, struct socket *socket)
{
    struct dnp_socket *ptr = NULL;
    list_for_each_entry(ptr, list, list)
    {
        if (ptr->sock == socket)
            return ptr;
    }

    return NULL;
}

int dnp_remove_socket(struct list_head *list, struct socket *sock)
{
    struct dnp_socket *dnp_socket = dnp_get_dnp_socket_by_socket(list, sock);
    if (!dnp_socket)
        return -EIO;

    list_del(&dnp_socket->list);

    return 0;
}

int dnp_add_sock(struct list_head *list, struct socket *sock)
{
    if (dnp_has_sock(list, sock))
    {
        return -EIO;
    }

    struct dnp_socket *dnp_socket = (struct dnp_socket *)kmalloc(sizeof(struct dnp_socket), GFP_USER);
    dnp_socket->sock = sock;

    list_add(&dnp_socket->list, list);

    return 0;
}