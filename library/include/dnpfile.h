#ifndef DNPFILE_H
#define DNPFILE_H

#include <string>
#include <fstream>
#include <mutex>
#include "dnp.h"
#include "cell.h"
#include "mmapcell.h"
// This is a bit dirty to be honest maybe a better solution can be achieved
#define TOTAL_IPS_IN_BLOCK (DNP_SECTOR_SIZE / sizeof(struct in_addr)) - sizeof(struct ip_block_header)
namespace Dnp
{

/**
     *  Dnp File format 
     * - file header
     * - data table header
     * - data table
     * - data scattered    
     */
struct file_header
{
    // Signature
    char signature[DNP_SIGNATURE_SIZE];
    // The version of this Dnp file
    DNP_FILE_FORMAT_VERSION version;
    // Total nodes available in the system
    unsigned long total_cells;
    // The absolute position of the first node
    CELL_POSITION first_cell;

    // The absolute position of the most recently created node
    CELL_POSITION last_cell;

    // The absolute position to the first ip table block
    IP_BLOCK_POSITION first_ip_block_position;

    // The absolute position of the current IP block that is not full
    IP_BLOCK_POSITION current_ip_block_position;
};

// Represents
struct data_table_header
{
    // Total sectors that can be used by this data table
    unsigned int total_sectors;
};

struct cell_header
{
    unsigned char id[MD5_HEX_SIZE];
    size_t size;
    CELL_FLAGS flags;

    CELL_RSA_KEY_POSITION public_key_pos;
    size_t public_key_size;

    CELL_RSA_KEY_POSITION private_key_pos;
    size_t private_key_size;

    CELL_HASH_POSITION encrypted_data_hash_pos;
    size_t encrypted_data_hash_size;

    CELL_DATA_POSITION data_pos;
    CELL_POSITION prev_cell_pos;
    CELL_POSITION next_cell_pos;
};

// Header must divide into 4 so that ip_block structure can fit into 512 byte count correctly and have an even number of ip addresses
struct ip_block_header
{
    unsigned int total_ips;
    unsigned long next_block_pos;
    // Must be here so we can divide into 4, reserved does nothing useful may become flags or something in the future
    unsigned int reserved;
};

struct ip_block
{
    struct ip_block_header ip_block_header;
    // A block of ip 124 ipv4 addresses for 512 byte sector count
    struct in_addr ip[TOTAL_IPS_IN_BLOCK];
};

class System;
class DnpFile
{
public:
    DnpFile(System *system);
    virtual ~DnpFile();
    void openFile(std::string filename);
    std::string getNodeFilename();

    bool getFileHeader(struct file_header *header);
    void createCell(Cell *cell);
    bool doesIpExist(std::string ip);
    void addIp(std::string ip);
    bool getNextIp(std::string &ip_str, unsigned long *current_index, unsigned long ip_block_pos = -1);
    bool loadCell(std::string cell_id, MemoryMappedCell &cell);
    bool deleteCell(const std::string &cell_id);
    bool updateCell(MemoryMappedCell &cell);

    /**
     * 
     * Returns the cell at the current_pos then sets the current_pos to the previous cell from the cell just loaded
     */
    bool iterateBackwards(MemoryMappedCell *cell, CELL_POSITION *current_pos);

private:
    off_t find(std::string cell_id, struct cell_header &tmp_header);
    void loadCellHeader(struct cell_header *cell_header, CELL_POSITION position);
    void loadCellFromHeader(struct cell_header &cell_header, MemoryMappedCell &cell);
    bool _doesIpExist(std::string ip);
    bool _loadCell(std::string cell_id, MemoryMappedCell &cell);
    bool _deleteCell(const std::string &cell_id);
    bool _updateCell(MemoryMappedCell &cell);
    void createCellTable();
    void loadFile(std::string filename);
    void setupFileAndOpen(std::string filename);
    void initFileHeader(struct file_header *header);
    void initCellHeader(struct cell_header *header);
    void initIpBlock(struct ip_block *ip_block);
    bool isIpBlockFull(unsigned long pos);

    /**
    * Creates an IP block in the file and returns its position
     */
    unsigned long createIpBlock();

    /**
     * Creates a new ip block if our current block is full
     */
    void createNewIpBlockIfNeeded();

    /**
     * Returns the  first available ip block and creates one if it does not exist
     */
    unsigned long getFirstIpBlock();

    /**
     * Reads and returns the ip block header for the ip block located at the given position
     */
    struct ip_block_header readIpBlockHeader(unsigned long pos);

    /**
             * Writes the given ip to the ip block represented by the pos variable that represents the position in the file
             * ensure that this is an ip block or have disastrous results
             */
    void writeIpToIpBlock(unsigned long pos, std::string ip);

    /**
     * Creates the first ip block in the system, should be called when setting up DNP file for the first time
     */
    void createFirstIPBlock();

    /**
     * Returns the current ip block in the system that is currently active and may have room for more IP addresses
     * All IP Blocks in the system are taken into consideration however the current ip block is the one that is not full yet
     */
    unsigned long getCurrentIpBlock();

    /**
     * Creates a new IP Block and makes it the current IP block
     */
    void createNewCurrentIpBlock();

    /**
     * Writes the provided ip block header header to the disk at the provided position
     */
    void writeIpBlockHeaderToDisk(unsigned long pos, struct ip_block_header &header);

    /**
             * Writes the current file header in memory to disk
             */
    void writeFileHeader();

    /**
             * Returns a free position in the DnpFile where you can safely write the provided size
             * If there is no room then zero is returned.
             */
    unsigned long getFreePositionForData(unsigned long size);
    /**
             * Returns a free position in the DnpFile where you can safely write the provided size
             * If there is no room then an exception is thrown
             */
    unsigned long getFreePositionForDataOrThrow(unsigned long size);

    /**
     * Seeks to the file object to the data table in the DNP file
     */
    inline void seek_to_data_table();

    void markInDataTableForPosition(off_t pos, size_t size, char b);

    /**
             * Marks the data as non free in the data table
             */
    void markDataTaken(off_t pos, size_t size);
    /**
     * Marks the data as free so that it can be overwritten by new writes
     */
    void markDataFree(off_t pos, size_t size);

    void seek_and_write(unsigned long pos, const char *data, unsigned long size);
    void seek_and_read(unsigned long pos, char *data, unsigned long size);

protected:
    std::mutex mutex;
    std::fstream node_file;
    std::string node_filename;
    struct file_header loaded_file_header;
    System *system;
};
}; // namespace Dnp

#endif