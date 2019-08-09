#ifndef TYPES_H
#define TYPES_H

typedef unsigned int PROTOCOL_VERSION;
typedef unsigned int DNP_FILE_FORMAT_VERSION;
typedef unsigned long NODE_ID;
typedef unsigned char NODE_FLAGS;
typedef unsigned long NODE_DATA_TABLE_OFFSET;
typedef unsigned long NODE_DATA_POSITION;
typedef unsigned long NODE_POSITION;

#define DNP_SECTOR_FREE 0x00
#define DNP_SECTOR_TAKEN 0xff


#endif