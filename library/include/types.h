#ifndef TYPES_H
#define TYPES_H

#define MD5_HEX_SIZE 32
#define MAX_PRIVATE_KEY_SIZE 4096
#define MAX_PUBLIC_KEY_SIZE 2048
#define MAX_ENCRYPTED_MD5_DATA_HASH_SIZE 256    

typedef unsigned int PROTOCOL_VERSION;
typedef unsigned int DNP_FILE_FORMAT_VERSION;
typedef unsigned char CELL_FLAGS;
typedef unsigned char CELL_FLAG;
typedef unsigned char NETWORK_CELL_FLAGS;
typedef unsigned long NODE_DATA_TABLE_OFFSET;
typedef unsigned long CELL_DATA_POSITION;
typedef unsigned long CELL_POSITION;
typedef unsigned long CELL_RSA_KEY_POSITION;
typedef unsigned long CELL_HASH_POSITION;
typedef unsigned long IP_BLOCK_POSITION;


#define DNP_SECTOR_FREE 0x00
#define DNP_SECTOR_TAKEN 0xff


#endif