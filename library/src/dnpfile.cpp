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
        setupFile(filename);
    } 
 
    loadFile(filename);
}


void DnpFile::loadFile(std::string filename)
{
    // Open the file
    this->node_file.open(filename, std::fstream::in | std::fstream::binary | std::fstream::out);

    // Load the file header
    this->node_file.read((char*) &this->loaded_file_header, sizeof(this->loaded_file_header));
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
        tmp_file.put(DNP_SECTOR_FREE);
    }

    tmp_file.close();
}

std::string DnpFile::getNodeFilename()
{
    return this->node_filename;
}

void DnpFile::writeFileHeader()
{
    this->node_file.seekp(0, this->node_file.beg);
    this->node_file.write((const char*) &this->loaded_file_header, sizeof(this->loaded_file_header));
}

void DnpFile::initFileHeader(struct file_header* header)
{
    memset(header, 0, sizeof(struct file_header));
    memcpy(header->signature, DNP_SIGNATURE, DNP_SIGNATURE_SIZE);
    header->version = CURRENT_DNP_FILE_FORMAT_VERSION;
}

void DnpFile::initNodeHeader(struct cell_header* header)
{
    memset(header, 0x00, sizeof(struct file_header));
}


void DnpFile::createCell(CELL_ID cell_id, unsigned long size, const char* data)
{
    // First check we have enough room for the data and the cell
    this->getFreePositionForDataOrThrow(size+sizeof(struct cell_header));

    // Get a valid position for the data
    unsigned long data_pos = this->getFreePositionForDataOrThrow(size);

    // Let's first write the data
    this->node_file.seekp(data_pos, this->node_file.beg);
    this->node_file.write(data, size);
    this->markDataTaken(data_pos, size);

    unsigned long cell_pos = this->getFreePositionForDataOrThrow(sizeof(struct cell_header));

    // Now create and write the cell header
    struct cell_header cell_header;
    initNodeHeader(&cell_header);

    cell_header.id = cell_id;
    cell_header.size = size;
    cell_header.prev_cell_pos = this->loaded_file_header.last_cell;
    cell_header.data_pos = data_pos;
    this->node_file.seekp(cell_pos, this->node_file.beg);
    this->node_file.write((const char*)&cell_header, sizeof(struct cell_header));

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
        this->node_file.seekp(this->loaded_file_header.last_cell+offsetof(struct cell_header, next_cell_pos), this->node_file.beg);
        this->node_file.write((const char*) &cell_pos, sizeof(cell_pos));
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
        this->node_file.put(DNP_SECTOR_TAKEN);
    }
}

bool DnpFile::loadCell(CELL_ID cell_id, struct cell_header* cell_header, char** data)
{
    *data = 0;

    // Read in the cell header
    struct cell_header tmp_header;
    unsigned long current_pos = this->loaded_file_header.first_cell;
    while(current_pos != 0)
    {
        this->node_file.seekp(current_pos, this->node_file.beg);
        // Read in the cell data
        this->node_file.read((char*) &tmp_header, sizeof(tmp_header));
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