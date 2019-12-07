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
    printk(KERN_INFO "Removing socket from list\n", __FUNCTION__);
    struct dnp_socket *dnp_socket = dnp_get_dnp_socket_by_socket(list, sock);
    if (!dnp_socket)
        return -EIO;

    list_del(&dnp_socket->list);
    printk(KERN_INFO "Leave\n", __FUNCTION__);

    return 0;
}

int dnp_add_sock(struct list_head *list, struct socket *sock)
{
    printk(KERN_INFO "Adding socket to list\n", __FUNCTION__);
    if (dnp_has_sock(list, sock))
    {
        return -EIO;
    }

    struct dnp_socket *dnp_socket = (struct dnp_socket *)kmalloc(sizeof(struct dnp_socket), GFP_USER);
    dnp_socket->sock = sock;

    list_add(&dnp_socket->list, list);
    printk(KERN_INFO "Leave\n", __FUNCTION__);

    return 0;
}