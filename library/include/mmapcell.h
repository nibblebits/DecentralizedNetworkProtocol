/*
Dnp Decentralized Network Protocol

Copyright (C) 2019  Daniel McCarthy
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef MMAP_CELL_H
#define MMAP_CELL_H
#include "cell.h"
#include <string>
namespace Dnp
{
class System;
class MemoryMappedCell : public Cell
{
public:
    MemoryMappedCell(Dnp::System *system);
    MemoryMappedCell(CELL_ID id, Dnp::System *system);
    virtual ~MemoryMappedCell();
   
    void setMappedData(std::string filename, off_t offset, size_t size);
protected:
    void closeMmapData();
private:
    void* mmap_data;
    size_t mmap_size;
    int mmap_fd;
};
} // namespace Dnp
#endif