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

void DnpFile::initIpBlock(struct ip_block *ip_block)
{
    memset(ip_block, 0x00, sizeof(struct ip_block));
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

bool DnpFile::_getDnpAddress(std::string address, struct dnp_address *dnp_address)
{
    DNP_ADDRESS_POSITION pos = this->loaded_file_header.first_dnp_address_position;
    while (pos != 0)
    {
        seek_and_read(pos, (char *)dnp_address, sizeof(*dnp_address));
        if (memcmp(dnp_address->address, address.c_str(), address.size()) == 0)
        {
            return true;
        }
        pos = dnp_address->next;
    }
    return false;
}

bool DnpFile::getDnpAddress(std::string address, struct dnp_address *dnp_address)
{
    std::lock_guard<std::mutex> lck(this->mutex);
    return this->_getDnpAddress(address, dnp_address);
}

bool DnpFile::hasDnpAddress(std::string address)
{
    std::lock_guard<std::mutex> lck(this->mutex);
    return this->_hasDnpAddress(address);
}

bool DnpFile::_hasDnpAddress(std::string address)
{
    struct dnp_address tmp_address;
    return this->_getDnpAddress(address, &tmp_address);
}

void DnpFile::_addDnpAddress(std::string address, std::string public_key, std::string private_key)
{
    if (public_key.empty() || address.empty())
    {
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "Expecting a public key and an address at the very least");
    }

    if (_hasDnpAddress(address))
    {
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "DNP Address is already registered with us");
    }

    struct dnp_address dnp_address;
    memset(&dnp_address, 0, sizeof(dnp_address));

    if (address.size() >= sizeof(dnp_address.address))
    {
        throw DnpException(DNP_EXCEPTION_UNSUPPORTED, "DNP Address is too large");
    }

    RSA_PUBLIC_KEY_POSITION pub_key_pos = this->getFreePositionForDataOrThrow(public_key.size());
    this->markDataTaken(pub_key_pos, public_key.size());
    this->seek_and_write(pub_key_pos, public_key.c_str(), public_key.size());
    RSA_PRIVATE_KEY_POSITION priv_key_pos = 0;
    if (!private_key.empty())
    {
        priv_key_pos = this->getFreePositionForDataOrThrow(private_key.size());
        this->markDataTaken(priv_key_pos, private_key.size());
        this->seek_and_write(priv_key_pos, private_key.c_str(), private_key.size());
    }

    DNP_ADDRESS_POSITION dnp_address_pos = this->getFreePositionForDataOrThrow(sizeof(struct dnp_address));
    this->markDataTaken(dnp_address_pos, sizeof(struct dnp_address));

    memcpy(dnp_address.address, address.c_str(), sizeof(dnp_address.address));
    dnp_address.public_key_pos = pub_key_pos;
    dnp_address.public_key_size = public_key.size();
    dnp_address.private_key_pos = priv_key_pos;
    dnp_address.private_key_size = private_key.size();
    seek_and_write(dnp_address_pos, (const char *)&dnp_address, sizeof(dnp_address));

    DNP_ADDRESS_POSITION dnp_address_last_pos = this->loaded_file_header.current_dnp_address_position;
    // Have we never created a DNP address before?
    if (dnp_address_last_pos == 0)
    {
        // No we have not then its the first DNP address in the system
        this->loaded_file_header.first_dnp_address_position = dnp_address_pos;
        this->loaded_file_header.current_dnp_address_position = dnp_address_pos;
    }
    else
    {
        // Ok lets append like a linked list
        struct dnp_address prev_dnp_address;
        this->seek_and_read(dnp_address_last_pos, (char *)&prev_dnp_address, sizeof(prev_dnp_address));
        prev_dnp_address.next = dnp_address_pos;
        this->seek_and_write(dnp_address_last_pos, (char *)&prev_dnp_address, sizeof(prev_dnp_address));
        this->loaded_file_header.current_dnp_address_position = dnp_address_pos;
    }

    this->writeFileHeader();
}

void DnpFile::addDnpAddress(std::string address, std::string public_key, std::string private_key)
{
    std::lock_guard<std::mutex> lock(this->mutex);
    this->_addDnpAddress(address, public_key, private_key);
}

void DnpFile::addIp(std::string ip)
{
    std::lock_guard<std::mutex> lock(this->mutex);
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
