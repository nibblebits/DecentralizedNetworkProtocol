#ifndef CONFIG_H

#define CURRENT_PROTOCOL_VERSION 1
#define CURRENT_DNP_FILE_FORMAT_VERSION 1
#define DNP_SIGNATURE_SIZE 3
#define DNP_SIGNATURE "DNP"
#define DNP_SECTOR_SIZE 4096
#define DNP_TOTAL_SECTORS_PER_TABLE 10000
#define DOMAIN_SERVER_PATH     "/tmp/dnp_server"
#define DOMAIN_SERVER_BUFFER_LENGTH    250

// Compiled in for now but in the future best to calculate this
#define MAX_TOTAL_THREADS 8

#endif