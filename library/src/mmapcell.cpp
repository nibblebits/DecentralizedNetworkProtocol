#include "mmapcell.h"
#include <sys/stat.h>
#include <sys/mman.h> 
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdexcept>
using namespace Dnp;
MemoryMappedCell::MemoryMappedCell(Dnp::System *system) : Cell(system)
{
    this->mmap_fd = -1;
    this->mmap_data = nullptr;
}

MemoryMappedCell::MemoryMappedCell(CELL_ID id, Dnp::System *system) : Cell(id, system)
{

}

MemoryMappedCell::~MemoryMappedCell()
{
    closeMmapData();
}

void MemoryMappedCell::closeMmapData()
{
    if (this->mmap_fd > 0)
    {
        close(this->mmap_fd);
    }

    if (this->mmap_data != nullptr)
    {
        munmap(this->mmap_data, this->mmap_size);
    }
}

void MemoryMappedCell::setMappedData(std::string filename, off_t offset, size_t size)
{
    closeMmapData();
    size_t offset_misalignment = offset % getpagesize();
    off_t page_offset = offset - offset_misalignment;
    size_t mmap_size = size + offset_misalignment;
    this->mmap_fd = open(filename.c_str(), O_RDONLY);
    this->mmap_data = mmap(0, mmap_size, PROT_READ, MAP_PRIVATE, this->mmap_fd, page_offset);
    this->mmap_size = mmap_size;

    if (this->mmap_data == MAP_FAILED)
    {
        throw std::logic_error("setMappedData() mmap failed sorry: " + std::string(strerror(errno)));
    }

    // As mmap data may not be pointing at correct offset let's readjust it for the actual data pointer
    char* data_ptr = (char*)((char*)this->mmap_data + offset_misalignment);
    this->setData(data_ptr, size);
}