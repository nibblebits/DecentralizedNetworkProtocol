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

#include "cell.h"
#include "system.h"

using namespace Dnp;

Cell::Cell(Dnp::System *system)
{
    this->system = system;
}
Cell::Cell(CELL_ID id, System* system)
{
    this->id = id;
    this->system = system;
}

Cell::~Cell()
{
    
}

void Cell::setFlags(CELL_FLAGS flags)
{
    this->flags = flags;
}
    
CELL_FLAGS Cell::getFlags()
{
    return this->flags;
}

void Cell::setId(CELL_ID id)
{
    this->id = id;
}

CELL_ID Cell::getId()
{
    return this->id;
}

unsigned long Cell::getDataSize()
{
    return this->data_size;
}

char* Cell::getData()
{
    return this->data;
}

void Cell::setData(char* data, unsigned long size)
{
    this->data = data;
    this->data_size = size;
}

void Cell::publish()
{
    // Send ourself
    this->system->getClientDomainSocket()->sendCell(this);
}