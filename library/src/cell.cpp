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
#include "misc.h"
#include "crypto/rsa.h"
#include <memory.h>
#include <iostream> 

using namespace Dnp;

Cell::Cell(Dnp::System *system)
{
    this->system = system;
    this->data = nullptr;
    this->data_size = -1;
    this->flags = 0;
    this->clearChanges();
}
Cell::Cell(std::string id, System *system) : Cell(system)
{
    this->id = id;
}

Cell::~Cell()
{
}

void Cell::setFlags(CELL_FLAGS flags)
{
    this->flags = flags;
    this->cell_changes.changed = true;
    this->cell_changes.flags_changed = true;
}

void Cell::setFlag(CELL_FLAG flag)
{
    this->flags |= flag;
    this->cell_changes.changed = true;
    this->cell_changes.flags_changed = true;
}

CELL_FLAGS Cell::getFlags()
{
    return this->flags;
}

void Cell::setId(std::string id)
{
    this->id = id;
}

void Cell::setPublicKey(std::string public_key)
{
    this->public_key = public_key;
}

void Cell::setPrivateKey(std::string private_key)
{
    this->private_key = private_key;
}

bool Cell::wasCellUpdated()
{
    return this->cell_changes.changed;
}

struct cell_changes Cell::getCellChanges()
{
    return this->cell_changes;
}
std::string Cell::getId()
{
    return this->id;
}

std::string Cell::getPublicKey()
{
    return this->public_key;
}

std::string Cell::getPrivateKey()
{
    return this->private_key;
}

bool Cell::hasPrivateKey()
{
    return this->private_key.size() > 0;
}
bool Cell::hasPublicKey()
{
    return this->public_key.size() > 0;
}

std::string Cell::getEncryptedHash()
{
    return this->encrypted_data_hash;
}


unsigned long Cell::getDataSize()
{
    return this->data_size;
}

char *Cell::getData()
{
    return this->data;
}

bool Cell::hasData()
{
    return this->data_size != 0;
}

bool Cell::hasEncryptedDataHash()
{
    return this->encrypted_data_hash.size() != 0;
}

void Cell::setData(char *data, unsigned long size)
{
    this->data = data;
    this->data_size = size;
    this->cell_changes.changed = true;
    this->cell_changes.data_changed = true;
    if (this->hasPrivateKey())
    {
        std::string data_str = std::string(data, size);
        std::string hash = md5_hex(data_str);
        std::string encrypted_hash = "";
        Rsa::encrypt_private(this->private_key, hash, encrypted_hash);
        this->setEncryptedDataHash(encrypted_hash); 
        std::cout << "Encrypted hash size: " << encrypted_hash.size() << std::endl;
    }
    this->setFlag(CELL_FLAG_DATA_LOCAL);
}

void Cell::setEncryptedDataHash(std::string data_hash)
{
    this->encrypted_data_hash = data_hash;
}

void Cell::clearChanges()
{
    memset(&this->cell_changes, 0, sizeof(this->cell_changes));
}
void Cell::publish()
{
    // Send ourself
    this->system->getClientDomainSocket()->sendCell(this);
}