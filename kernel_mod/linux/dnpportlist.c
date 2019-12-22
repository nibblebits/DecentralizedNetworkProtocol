#include "dnp.h"

bool dnp_is_port_set(struct list_head* list, __u16 port)
{
    struct dnp_binded_port* ptr = NULL;
    list_for_each_entry(ptr, list, list)
    {
        if (ptr->port == port)
            return true;
    }

    return false;
}


struct dnp_binded_port* dnp_get_port_by_socket(struct list_head* list, struct socket* socket)
{
    struct dnp_binded_port* ptr = NULL;
    list_for_each_entry(ptr, list, list)
    {
        if (ptr->sock == socket)
            return ptr;
    }

    return NULL;
}


int dnp_remove_port(struct list_head* list, struct socket* sock)
{
    struct dnp_binded_port* binded_port = dnp_get_port_by_socket(list, sock);
    if (!binded_port)
        return -EIO;

    list_del(&binded_port->list);
    kfree(binded_port);
    return 0;
}


int dnp_set_port(struct list_head* list, __u16 port, struct socket* sock)
{
    struct dnp_binded_port* binded_port = (struct dnp_binded_port*) kzalloc(sizeof(struct dnp_binded_port), GFP_USER);
    binded_port->sock = sock;
    binded_port->port = port;

    if (dnp_is_port_set(list, port))
    {
        return -EADDRINUSE;
    }


    list_add(&binded_port->list, list);
    return 0;
}