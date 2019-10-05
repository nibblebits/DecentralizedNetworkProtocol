#include "dnpfile.h"
#include "types.h"
#include "memory.h"
#include "dnpexception.h"
#include "system.h"
#include <stddef.h>
#include <stdio.h>
#include <iostream>
#include <exception>
#include <experimental/filesystem>
using namespace Dnp;
DnpFile::DnpFile(System *system)
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
    std::lock_guard<std::mutex> lock(this->mutex);
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

bool DnpFile::getFileHeader(struct file_header *header)
{
    memcpy(header, &this->loaded_file_header, sizeof(struct file_header));
    return true;
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

bool DnpFile::iterateBackwards(MemoryMappedCell *cell, CELL_POSITION *current_pos)
{
    if (*current_pos == 0)
    {
        // We have reached the end
        return false;
    }

    std::lock_guard<std::mutex> lock(this->mutex);
    struct cell_header header;
    this->loadCellHeader(&header, *current_pos);
    this->loadCellFromHeader(header, *cell);

    // Set the current position to the previous cell
    *current_pos = header.prev_cell_pos;
    return true;
}

void DnpFile::seek_and_write(unsigned long pos, const char *data, unsigned long size)
{
    this->node_file.seekp(pos);
    this->node_file.write(data, size);
}

void DnpFile::seek_and_read(unsigned long pos, char *data, unsigned long size)
{
    this->node_file.seekp(pos);
    this->node_file.read(data, size);
}

void DnpFile::createCell(Cell *cell)
{
    if (!cell->hasEncryptedDataHash())
    {
        throw std::logic_error("createCell(): no encrypted data hash provided");
    }

    struct cell_header tmp_header;
    if (find(cell->getId(), tmp_header) != 0)
    {
        // Cell exists, so we don't want to create a duplicate let's leave
        return;
    }

    std::lock_guard<std::mutex> lock(this->mutex);
    std::string cell_id = cell->getId();
    unsigned long size = cell->getDataSize();
    const char *data = cell->getData();
    CELL_FLAGS flags = cell->getFlags();
    std::string public_key = cell->getPublicKey();
    std::string private_key = cell->getPrivateKey();
    std::string encrypted_hash = cell->getEncryptedHash();

    // We got the data set the local flag
    if (data != nullptr)
    {
        flags |= CELL_FLAG_DATA_LOCAL;
    }

    // First check we have enough room for the data and the cell
    size_t total_size_needed = size + sizeof(struct cell_header);
    if (flags & CELL_FLAG_PRIVATE_KEY_HOLDER)
    {
        total_size_needed += public_key.size();
        total_size_needed += private_key.size();
    }

    this->getFreePositionForDataOrThrow(total_size_needed);

    // Get a valid position for the public key
    unsigned long public_key_pos = this->getFreePositionForDataOrThrow(public_key.size());
    seek_and_write(public_key_pos, public_key.c_str(), public_key.size());
    this->markDataTaken(public_key_pos, public_key.size());

    unsigned long private_key_pos = 0;
    unsigned long encrypted_hash_pos = 0;
    if (flags & CELL_FLAG_PRIVATE_KEY_HOLDER)
    {
        // Write the private key
        private_key_pos = this->getFreePositionForDataOrThrow(private_key.size());
        seek_and_write(private_key_pos, private_key.c_str(), private_key.size());
        this->markDataTaken(private_key_pos, private_key.size());
    }

    // Write the encrypted hash
    encrypted_hash_pos = this->getFreePositionForDataOrThrow(encrypted_hash.size());
    seek_and_write(encrypted_hash_pos, encrypted_hash.c_str(), encrypted_hash.size());

    // Get a valid position for the data
    unsigned long data_pos = this->getFreePositionForDataOrThrow(size);

    // Let's first write the data
    seek_and_write(data_pos, data, size);
    this->markDataTaken(data_pos, size);

    unsigned long cell_pos = this->getFreePositionForDataOrThrow(sizeof(struct cell_header));

    // Now create and write the cell header
    struct cell_header cell_header;
    initCellHeader(&cell_header);
    if (cell_id.size() != MD5_HEX_SIZE)
    {
        throw Dnp::DnpException(DNP_EXCEPTION_ILLEGAL_CELL, "Provided cell has an illegal cell id, size does not equal MD5_HEX_SIZE: " + std::to_string(MD5_HEX_SIZE));
    }
    memcpy(cell_header.id, cell_id.c_str(), cell_id.size());

    cell_header.size = size;
    cell_header.flags = flags;
    cell_header.prev_cell_pos = this->loaded_file_header.last_cell;
    cell_header.public_key_pos = public_key_pos;
    cell_header.public_key_size = public_key.size();
    cell_header.private_key_pos = private_key_pos;
    cell_header.private_key_size = private_key.size();
    cell_header.encrypted_data_hash_pos = encrypted_hash_pos;
    cell_header.encrypted_data_hash_size = encrypted_hash.size();
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

void DnpFile::seek_to_data_table()
{
    this->node_file.seekp(sizeof(struct file_header), this->node_file.beg);
}

void DnpFile::markInDataTableForPosition(off_t pos, size_t size, char b)
{
    // Position us just after the file header, so that we point at the data table
    this->seek_to_data_table();

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
        this->node_file.put(b);
    }
}

void DnpFile::markDataTaken(off_t pos, size_t size)
{
    this->markInDataTableForPosition(pos, size, DNP_SECTOR_TAKEN);
}

void DnpFile::markDataFree(off_t pos, size_t size)
{
    this->markInDataTableForPosition(pos, size, DNP_SECTOR_FREE);
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
    std::lock_guard<std::mutex> lock(this->mutex);
    return this->_doesIpExist(ip);
}

bool DnpFile::_doesIpExist(std::string ip)
{
    std::string ip_str;
    unsigned long current_index = 0;
    while (getNextIp(ip_str, &current_index))
    {
        if (ip_str == ip)
            return true;
    }

    return false;
}

void DnpFile::addIp(std::string ip)
{
    //   std::lock_guard<std::mutex> lock(this->mutex);
    // Ip exists then we will not add it twice
    if (_doesIpExist(ip))
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
    std::lock_guard<std::mutex> lock(this->mutex);
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

off_t DnpFile::find(std::string cell_id, struct cell_header &tmp_header)
{
    off_t current_pos = this->loaded_file_header.first_cell;
    while (current_pos != 0)
    {
        loadCellHeader(&tmp_header, current_pos);
        if (memcmp(&tmp_header.id, cell_id.c_str(), MD5_HEX_SIZE) == 0)
        {
            break;
        }
        current_pos = tmp_header.next_cell_pos;
    }

    return current_pos;
}

bool DnpFile::_updateCell(MemoryMappedCell &cell)
{
    struct cell_header tmp_header;
    off_t header_offset = this->find(cell.getId(), tmp_header);
    if (header_offset == 0)
        return false;

    // Cell was not updated? Then we are done here
    if (!cell.wasCellUpdated())
    {
        return false;
    }

    struct cell_changes changes = cell.getCellChanges();
    if (changes.flags_changed)
    {
        tmp_header.flags = cell.getFlags();
        this->seek_and_write(header_offset + offsetof(struct cell_header, flags), (const char *)&tmp_header.flags, sizeof(tmp_header.flags));
    }

    // Cell was updated clear the changes
    cell.clearChanges();
    return true;
}

bool DnpFile::updateCell(MemoryMappedCell &cell)
{
    std::lock_guard<std::mutex> lock(this->mutex);
    return this->_updateCell(cell);
}

void DnpFile::loadCellHeader(struct cell_header *cell_header, CELL_POSITION position)
{
    this->node_file.seekp(position, this->node_file.beg);
    // Read in the cell data
    this->node_file.read((char *)cell_header, sizeof(struct cell_header));
}

void DnpFile::loadCellFromHeader(struct cell_header &cell_header, MemoryMappedCell &cell)
{

    // We found it copy over the header into the returning header
    if (cell_header.flags & CELL_FLAG_DATA_LOCAL)
    {
        cell.setMappedData(this->node_filename, cell_header.data_pos, cell_header.size);
        std::unique_ptr<char[]> encrypted_data_hash = std::make_unique<char[]>(cell_header.encrypted_data_hash_size);
        this->seek_and_read(cell_header.encrypted_data_hash_pos, encrypted_data_hash.get(), cell_header.encrypted_data_hash_size);
        cell.setEncryptedDataHash(std::string((char *)encrypted_data_hash.get(), cell_header.encrypted_data_hash_size));
    }

    cell.setFlags(cell_header.flags);
    cell.setId(std::string((char *)cell_header.id, sizeof(cell_header.id)));

    std::unique_ptr<char[]> public_key(new char[cell_header.public_key_size]);
    seek_and_read(cell_header.public_key_pos, public_key.get(), cell_header.public_key_size);
    cell.setPublicKey(std::string((char *)public_key.get(), cell_header.public_key_size));

    if (cell_header.flags & CELL_FLAG_PRIVATE_KEY_HOLDER)
    {
        std::unique_ptr<char[]> private_key(new char[cell_header.private_key_size]);
        seek_and_read(cell_header.private_key_pos, private_key.get(), cell_header.private_key_size);
        cell.setPrivateKey(std::string((char *)private_key.get(), cell_header.private_key_size));
    }

    // Clear the changes of this cell as its fully updated
    cell.clearChanges();
}

bool DnpFile::_loadCell(std::string cell_id, MemoryMappedCell &cell)
{
    // Read in the cell header
    struct cell_header tmp_header;
    if (this->find(cell_id, tmp_header) == 0)
        return false;

    loadCellFromHeader(tmp_header, cell);
    return true;
}

bool DnpFile::loadCell(std::string cell_id, MemoryMappedCell &cell)
{
    std::lock_guard<std::mutex> lock(this->mutex);
    this->_loadCell(cell_id, cell);
}

bool DnpFile::_deleteCell(const std::string &cell_id)
{
    struct cell_header tmp_header;
    off_t header_offset = find(cell_id, tmp_header);
    if (!header_offset)
    {
        std::cout << "Failed to delete " << cell_id << std::endl;
        return false;
    }
    if (tmp_header.flags & CELL_FLAG_DATA_LOCAL)
    {
        this->markDataFree(tmp_header.data_pos, tmp_header.size);
        this->markDataFree(tmp_header.encrypted_data_hash_pos, tmp_header.size);
        this->loaded_file_header.total_cells -= 1;
        if (this->loaded_file_header.first_cell == header_offset)
        {
            this->loaded_file_header.first_cell = 0;
        }
    }

    if (tmp_header.flags & CELL_FLAG_PRIVATE_KEY_HOLDER)
    {
        this->markDataFree(tmp_header.private_key_pos, tmp_header.private_key_size);
    }

    this->markDataFree(tmp_header.public_key_pos, tmp_header.public_key_size);

    // Rewrite the file header to update any major changes to the file
    this->writeFileHeader();

    return true;
}

bool DnpFile::deleteCell(const std::string &cell_id)
{
    std::lock_guard<std::mutex> lock(this->mutex);
    this->_deleteCell(cell_id);
}