#ifndef DNPFAMILY_H
#define DNPFAMILY_H

#include "dnp.h"
int dnp_family_init(void);
void dnp_family_exit(void);
int dnp_proto_register(const struct dnp_protocol *dnp_proto);
void dnp_proto_unregister(const struct dnp_protocol *dnp_proto);
#endif