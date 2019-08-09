#include "dnpfile.h"
#include "types.h"
#include "memory.h"
#include <iostream>
#include <exception>
#include <experimental/filesystem>
using namespace Dnp;
DnpFile::DnpFile()
{

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
        setupFile(filename);
    } 
 
    loadFile(filename);
}


void DnpFile::loadFile(std::string filename)
{
    // Open the file
    this->node_file.open(filename, std::fstream::in | std::fstream::binary | std::fstream::out);
}

void DnpFile::setupFile(std::string filename)
{

    // Open the file
    std::ofstream tmp_file;
    tmp_file.open(filename, std::fstream::binary | std::fstream::out);
    struct file_header header;
    initFileHeader(&header);

    // Write the header
    tmp_file.write((const char*)&header, sizeof(header));

    // Write the data table header
    struct data_table_header table_header;
    table_header.total_sectors = DNP_TOTAL_SECTORS_PER_TABLE;
    tmp_file.write((const char*) &table_header, sizeof(table_header));
     
    // Let's now write the bytes to represent the sectors
    for (int i = 0; i < table_header.total_sectors; i++)
    {
        tmp_file.put(DNP_SECTOR_TAKEN);
    }

    tmp_file.close();
}

std::string DnpFile::getNodeFilename()
{
    return this->node_filename;
}

void DnpFile::initFileHeader(struct file_header* header)
{
    memset(header, 0, sizeof(struct file_header));
    memcpy(header->signature, DNP_SIGNATURE, DNP_SIGNATURE_SIZE);
    header->version = CURRENT_DNP_FILE_FORMAT_VERSION;
}

void DnpFile::initNodeHeader(struct node_header* header)
{
    memset(header, 0, sizeof(struct file_header));
}


void DnpFile::createNode(NODE_ID node_id, unsigned long size, const char* data)
{
    unsigned long pos = this->getFreePositionForData(size);
    if (pos == 0)
    {
        throw std::logic_error("Out of space!");
    }

    this->node_file.seekp(pos, this->node_file.beg);

    struct node_header node_header;
    initNodeHeader(&node_header);

    node_header.id = node_id;
    node_header.size = size;
    this->node_file.write((const char*)&node_header, sizeof(struct node_header));

    // Mark this node as taken
    this->markDataTaken(pos, size);

}

unsigned long DnpFile::getFreePositionForData(unsigned long size)
{
    // Position us just after the file header, so that we point at the data table
    this->node_file.seekp(sizeof(struct file_header), this->node_file.beg);

    struct data_table_header table_header;
    this->node_file.read((char*) &table_header, sizeof(table_header));

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


void DnpFile::markDataTaken(unsigned long pos, unsigned long size)
{
    // Position us just after the file header, so that we point at the data table
    this->node_file.seekp(sizeof(struct file_header), this->node_file.beg);

    struct data_table_header table_header;
    this->node_file.read((char*) &table_header, sizeof(table_header));

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
        this->node_file.put(0xaa);
    }
}

void DnpFile::loadNode(unsigned long node_id)
{

}