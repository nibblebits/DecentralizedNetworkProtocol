#include "mmapcell.h"
#include "misc.h"
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
    this->mmap_data_fd = -1;
    this->mmap_data = nullptr;
    this->mmap_data_size = 0;
}

MemoryMappedCell::MemoryMappedCell(std::string id, Dnp::System *system) : Cell(id, system)
{
}

MemoryMappedCell::~MemoryMappedCell()
{
    closeMmapData();
}

void MemoryMappedCell::closeMmapData()
{
    if (this->mmap_data_fd > 0)
    {
        close(this->mmap_data_fd);
    }

    if (this->mmap_data != nullptr)
    {
        munmap(this->mmap_data, this->mmap_data_size);
    }


    setData(nullptr, -1);

}

void MemoryMappedCell::setMappedData(std::string filename, off_t offset, size_t size)
{

    closeMmapData();
    char *data_ptr = nullptr;
    map_data(filename, offset, size, this->mmap_data_fd, &this->mmap_data, this->mmap_data_size, &data_ptr);
    this->setData(data_ptr, size);
}
