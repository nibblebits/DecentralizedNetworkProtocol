
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h>   /* Needed for the macros */

#include "dnp.h"
#include "dnpfamily.h"
#include "dnpdatagramprotocol.h"

///< The license type -- this affects runtime behavior
MODULE_LICENSE("GPL");

///< The author -- visible when you use modinfo
MODULE_AUTHOR("Daniel McCarthy");

///< The description -- see modinfo
MODULE_DESCRIPTION("DNP Network Module");

///< The version of the module
MODULE_VERSION("0.1");

static int __init dnp_start(void)
{
    printk(KERN_INFO "Loading DNP module.\n");
    dnp_family_init();
    dnpdatagramprotocol_init();
    return 0;
}

static void __exit dnp_end(void)
{
    printk(KERN_INFO "Unloading DNP module.\n");
    dnp_family_exit();
    dnpdatagramprotocol_exit();
}

module_init(dnp_start);
module_exit(dnp_end);
