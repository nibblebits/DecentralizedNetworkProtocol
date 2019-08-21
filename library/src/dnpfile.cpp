#include "dnpfile.h"
#include "types.h"
#include "memory.h"
#include <stddef.h>
#include <stdio.h>
#include <iostream>
#include <exception>
#include <experimental/filesystem>
using namespace Dnp;
DnpFile::DnpFile()
{
    memset(&this->loaded_file_header, 0, sizeof(this->loaded_file_header));
}

DnpFile::~DnpFile()
{
    if (this->node_file.is_open())
    {
        this->node_file.close();
    }
}

void DnpFile::openFile(std::string filename)
{
    this->node_filename = filename;

    bool exists = std::experimental::filesystem::exists(filename);
    if (!exists)
    {
        // DNP file does not exist create it
        setupFileAndOpen(filename);
    }
    else
    {
        loadFile(filename);
    }
}

void DnpFile::loadFile(std::string filename)
{
    // Open the file
    this->node_file.open(filename, std::fstream::in | std::fstream::binary | std::fstream::out);

    // Load the file header
    this->node_file.read((char *)&this->loaded_file_header, sizeof(this->loaded_file_header));
}

void DnpFile::setupFileAndOpen(std::string filename)
{

    // Open the file
    std::ofstream tmp_file;
    tmp_file.open(filename, std::fstream::binary | std::fstream::out);
    struct file_header header;
    initFileHeader(&header);

    // Write the header
    tmp_file.write((const char *)&header, sizeof(header));

    // Write the data table header
    struct data_table_header table_header;
    table_header.total_sectors = DNP_TOTAL_SECTORS_PER_TABLE;
    tmp_file.write((const char *)&table_header, sizeof(table_header));

    // Let's now write the bytes to represent the sectors
    for (int i = 0; i < table_header.total_sectors; i++)
    {
        tmp_file.put(DNP_SECTOR_FREE);
    }

    tmp_file.close();

    // Ok load the file again so its open for reading and writing and then write the first IP block, not entirely ideal could be better..
    loadFile(filename);
    this->createFirstIPBlock();
    this->writeFileHeader();
}

std::string DnpFile::getNodeFilename()
{
    return this->node_filename;
}

void DnpFile::writeFileHeader()
{
    this->node_file.seekp(0, this->node_file.beg);
    this->node_file.write((const char *)&this->loaded_file_header, sizeof(this->loaded_file_header));
}

void DnpFile::initFileHeader(struct file_header *header)
{
    memset(header, 0x00, sizeof(struct file_header));
    memcpy(header->signature, DNP_SIGNATURE, DNP_SIGNATURE_SIZE);
    header->version = CURRENT_DNP_FILE_FORMAT_VERSION;
}

void DnpFile::initCellHeader(struct cell_header *header)
{
    memset(header, 0x00, sizeof(struct cell_header));
}

void DnpFile::initIpBlock(struct ip_block *ip_block)
{
    memset(ip_block, 0x00, sizeof(struct ip_block));
}

void DnpFile::createCell(CELL_ID cell_id, unsigned long size, const char *data)
{
    // First check we have enough room for the data and the cell
    this->getFreePositionForDataOrThrow(size + sizeof(struct cell_header));

    // Get a valid position for the data
    unsigned long data_pos = this->getFreePositionForDataOrThrow(size);

    // Let's first write the data
    this->node_file.seekp(data_pos, this->node_file.beg);
    this->node_file.write(data, size);
    this->markDataTaken(data_pos, size);

    unsigned long cell_pos = this->getFreePositionForDataOrThrow(sizeof(struct cell_header));

    // Now create and write the cell header
    struct cell_header cell_header;
    initCellHeader(&cell_header);

    cell_header.id = cell_id;
    cell_header.size = size;
    cell_header.prev_cell_pos = this->loaded_file_header.last_cell;
    cell_header.data_pos = data_pos;
    this->node_file.seekp(cell_pos, this->node_file.beg);
    this->node_file.write((const char *)&cell_header, sizeof(struct cell_header));

    // Mark this node as taken
    this->markDataTaken(cell_pos, size);

    // Is this the first node?
    if (this->loaded_file_header.first_cell == 0)
    {
        this->loaded_file_header.first_cell = cell_pos;
    }
    else
    {
        // This was not the first node so let's adjust the previous nodes next position to point to us
        this->node_file.seekp(this->loaded_file_header.last_cell + offsetof(struct cell_header, next_cell_pos), this->node_file.beg);
        this->node_file.write((const char *)&cell_pos, sizeof(cell_pos));
    }

    // Update the file header
    this->loaded_file_header.last_cell = cell_pos;
    this->loaded_file_header.total_cells++;

    // Update the header on disk
    this->writeFileHeader();
}

unsigned long DnpFile::getFreePositionForData(unsigned long size)
{
    // Position us just after the file header, so that we point at the data table
    this->node_file.seekp(sizeof(struct file_header), this->node_file.beg);

    struct data_table_header table_header;
    this->node_file.read((char *)&table_header, sizeof(table_header));

    unsigned long sector_descriptor_pos = this->node_file.tellp();
    unsigned long end_of_data_table_pos = sector_descriptor_pos + table_header.total_sectors;
    unsigned long first_free_pos = 0;
    int total_free_in_row = 0;
    int total_free_bytes_sum = 0;
    for (int i = 0; i < table_header.total_sectors; i++)
    {
        char sector_state = (char)this->node_file.get();
        if (sector_state == DNP_SECTOR_FREE)
        {
            // We found a free sector
            if (total_free_in_row == 0)
            {
                // Yes this was the first found, so set the first free position
                first_free_pos = i * DNP_SECTOR_SIZE;
            }
            total_free_in_row++;
            total_free_bytes_sum += DNP_SECTOR_SIZE;
            if (total_free_bytes_sum >= size)
            {
                unsigned long abs_pos = end_of_data_table_pos + first_free_pos;
                return abs_pos;
            }
        }
        else
        {
            first_free_pos = 0;
            total_free_in_row = 0;
            total_free_bytes_sum = 0;
        }
    }

    // Nothing found :(
    return 0;
}

unsigned long DnpFile::getFreePositionForDataOrThrow(unsigned long size)
{
    unsigned long pos = this->getFreePositionForData(size);
    if (pos == 0)
        throw std::logic_error("Out of space");

    return pos;
}

void DnpFile::markDataTaken(unsigned long pos, unsigned long size)
{
    // Position us just after the file header, so that we point at the data table
    this->node_file.seekp(sizeof(struct file_header), this->node_file.beg);

    struct data_table_header table_header;
    this->node_file.read((char *)&table_header, sizeof(table_header));

    unsigned long sector_descriptor_pos = this->node_file.tellp();
    unsigned long end_of_data_table_pos = sector_descriptor_pos + table_header.total_sectors;

    // We now point at the data in the table its self, lets get the relative position
    unsigned long rel_pos = pos - end_of_data_table_pos;
    // Get the sector number
    unsigned long sec_no = rel_pos / DNP_SECTOR_SIZE;
    // Get the absolute position of the sector number
    unsigned long sec_no_pos = sector_descriptor_pos + sec_no;
    // Total sectors to mark as taken
    unsigned long total_sectors = size / DNP_SECTOR_SIZE;
#warning REFACTOR BELOW, NOT GOOD
    if (size < DNP_SECTOR_SIZE)
    {
        total_sectors = 1;
    }
    // Position us!
    this->node_file.seekp(sec_no_pos, this->node_file.beg);
    for (int i = 0; i < total_sectors; i++)
    {
        this->node_file.put(DNP_SECTOR_TAKEN);
    }
}

struct ip_block_header DnpFile::readIpBlockHeader(unsigned long pos)
{
    struct ip_block_header ip_block_header;
    this->node_file.seekp(pos);
    this->node_file.read((char *)&ip_block_header, sizeof(ip_block_header));
    return ip_block_header;
}

unsigned long DnpFile::createIpBlock()
{
    // We have no IP block this is our very first ip address lets add the thing
    struct ip_block ip_block;
    initIpBlock(&ip_block);
    memset(&ip_block, 0x00, sizeof(ip_block));
    unsigned long pos = this->getFreePositionForDataOrThrow(sizeof(ip_block));
    // Great we got our position for our ip address block let's write our ip to our block and write the thing to disk
    ip_block.ip_block_header.total_ips = 0;
    this->node_file.seekp(pos, this->node_file.beg);
    this->node_file.write((const char *)&ip_block, sizeof(ip_block));
    // Mark that data as taken, don't want it being overwritten
    markDataTaken(pos, sizeof(ip_block));
    return pos;
}

void DnpFile::createFirstIPBlock()
{
    if (this->loaded_file_header.first_ip_block_position == 0)
    {
        unsigned long pos = createIpBlock();
        // Don't forget to add the first ip block in the file header
        this->loaded_file_header.first_ip_block_position = pos;
        // Since this is the first IP block it also becomes our current IP block
        this->loaded_file_header.current_ip_block_position = pos;
        this->writeFileHeader();
    }
}

unsigned long DnpFile::getFirstIpBlock()
{
    return this->loaded_file_header.first_ip_block_position;
}

bool DnpFile::isIpBlockFull(unsigned long pos)
{
    struct ip_block_header ip_block_header = readIpBlockHeader(pos);
    if (ip_block_header.total_ips >= TOTAL_IPS_IN_BLOCK)
    {
        std::cout << "Ips: " << ip_block_header.total_ips << std::endl;
    }
    return ip_block_header.total_ips >= TOTAL_IPS_IN_BLOCK;
}

void DnpFile::writeIpToIpBlock(unsigned long pos, std::string ip)
{
    // Let's make sure we have enough room
    if (isIpBlockFull(pos))
    {
        // We are out of bounds! reject this!
        throw std::logic_error("Position is out of bounds create a new IP block!");
    }

    // Let's read in that ip block header so we have an idea of where to put this ip address in the file
    struct ip_block_header ip_block_header = readIpBlockHeader(pos);
    // Convert our string ip address into a 4 byte integer representing a valid Ipv4 address
    struct in_addr ip_address; /* Internet address Ipv4.  */
    inet_pton(AF_INET, ip.c_str(), &ip_address);

    // Where we are writing our ip address
    // ip_block holds ip_block_header and ip list so we offsetof to the beginning of the ip list
    unsigned long ip_rel_pos = (ip_block_header.total_ips * sizeof(struct in_addr)) + offsetof(struct ip_block, ip);
    unsigned long ip_pos_abs = pos + ip_rel_pos;

    this->node_file.seekp(ip_pos_abs, this->node_file.beg);
    this->node_file.write((const char *)&ip_address, sizeof(ip_address));

    // Let's update the ip block header
    ip_block_header.total_ips++;

    // Now write the thing back to disk
    this->writeIpBlockHeaderToDisk(pos, ip_block_header);
}

void DnpFile::writeIpBlockHeaderToDisk(unsigned long pos, struct ip_block_header &header)
{
    this->node_file.seekp(pos, this->node_file.beg);
    this->node_file.write((const char *)&header, sizeof(struct ip_block_header));
}

void DnpFile::createNewIpBlockIfNeeded()
{
    if (this->isIpBlockFull(this->loaded_file_header.current_ip_block_position))
    {
        // The block is full, lets create another!
        this->createNewCurrentIpBlock();
    }
}

bool DnpFile::doesIpExist(std::string ip)
{
    std::string ip_str;
    unsigned long current_index = 0;
    while (getNextIp(ip_str, &current_index))
    {
        if (ip_str == ip)
            return false;
    }

    return true;
}

void DnpFile::addIp(std::string ip)
{
    // Ip exists then we will not add it twice
    if (doesIpExist(ip))
        return;

    // Create a new ip block if our current block is full
    createNewIpBlockIfNeeded();

    unsigned long ip_block_pos = this->getCurrentIpBlock();
    writeIpToIpBlock(ip_block_pos, ip);
}

void DnpFile::createNewCurrentIpBlock()
{
    /* Ok we are creating a new IP block that will become the new current
       we must first take the current IP block and save its position we are going to need it soon
       we will create the new IP block and link the old IP block to the new one and then replace the current ip block
       with the new one in the DNP file header. Think Linked List!
    */

    unsigned long current_ip_block_pos = this->loaded_file_header.current_ip_block_position;
    unsigned long new_ip_block_pos = this->createIpBlock();
    // This points to the linked list next variable that points to our new IP block
    unsigned long pos_to_next_block_pos_var = offsetof(struct ip_block_header, next_block_pos) + current_ip_block_pos;
    // Great we got a new ip block created, let's now change the current ip block's pointer to point to the new ip block
    this->node_file.seekp(pos_to_next_block_pos_var, this->node_file.beg);
    this->node_file.write((char *)&new_ip_block_pos, sizeof(new_ip_block_pos));

    // Finally we adjust the DNP file header and attach the current IP block
    this->loaded_file_header.current_ip_block_position = new_ip_block_pos;
    this->writeFileHeader();
}

unsigned long DnpFile::getCurrentIpBlock()
{
    return this->loaded_file_header.current_ip_block_position;
}

bool DnpFile::getNextIp(std::string &ip_str, unsigned long *current_index, unsigned long ip_block_pos)
{
    // No IP block position provided then default to the first block!
    if (ip_block_pos == -1)
    {
        ip_block_pos = this->getFirstIpBlock();
    }
    struct ip_block ip_block;
    this->node_file.seekp(ip_block_pos, this->node_file.beg);
    this->node_file.read((char *)&ip_block, sizeof(ip_block));

    // Current index out of bounds, then we are done here if there is no next block
    if (*current_index >= ip_block.ip_block_header.total_ips)
    {
        if (ip_block.ip_block_header.next_block_pos != 0)
        {
            std::cout << "going to next block: " << ip_block.ip_block_header.next_block_pos << std::endl;
            *current_index = 0;
            return getNextIp(ip_str, current_index, ip_block.ip_block_header.next_block_pos);
        }
        return false;
    }

    struct in_addr ip_int;
    unsigned long ip_pos = ip_block_pos + offsetof(struct ip_block, ip) + (*current_index * sizeof(struct in_addr));
    this->node_file.seekp(ip_pos);
    this->node_file.read((char *)&ip_int, sizeof(ip_int));

    // Convert that IP address back to a string
    char ip_str_buf[INET_ADDRSTRLEN];
    memset(&ip_str_buf, 0, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_int, ip_str_buf, INET_ADDRSTRLEN);
    // We got it as a char buffer lets set the ip_str so the caller now knows the next ip address

    ip_str = std::string(ip_str_buf);
    *current_index += 1;

    return true;
}

bool DnpFile::loadCell(CELL_ID cell_id, struct cell_header *cell_header, char **data)
{
    *data = 0;

    // Read in the cell header
    struct cell_header tmp_header;
    unsigned long current_pos = this->loaded_file_header.first_cell;
    while (current_pos != 0)
    {
        this->node_file.seekp(current_pos, this->node_file.beg);
        // Read in the cell data
        this->node_file.read((char *)&tmp_header, sizeof(tmp_header));
        if (tmp_header.id == cell_id)
        {
            // We found it copy over the header into the returning header
            *data = new char[tmp_header.size];
            this->node_file.seekp(tmp_header.data_pos, this->node_file.beg);
            this->node_file.read(*data, tmp_header.size);
            memcpy(cell_header, &tmp_header, sizeof(tmp_header));
            return true;
        }

        current_pos = tmp_header.next_cell_pos;
    }

    return false;
}