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

#ifndef CELL_H
#define CELL_H
#include "types.h"
#include <string>
namespace Dnp
{
class System;

struct cell_changes
{   
    bool changed;
    bool flags_changed;
    bool data_changed;
};

class Cell
{
public:
    Cell(Dnp::System *system);
    Cell(std::string id, Dnp::System *system);
    virtual ~Cell();
        
    void setId(std::string id);
    void setPublicKey(std::string public_key);
    void setPrivateKey(std::string public_key);

    void setFlags(CELL_FLAGS flags);
    void setFlag(CELL_FLAG flag);
    void setData(char *data, unsigned long size);

    bool hasData();
    
    /**
     * Clears the defined changes not the changes themselves
     */
    void clearChanges();

    bool wasCellUpdated();
    struct cell_changes getCellChanges();

    std::string getId();
    std::string getPublicKey();
    std::string getPrivateKey();
    CELL_FLAGS getFlags();
    char *getData();


    unsigned long getDataSize();
    void publish();

protected:
    // The numeric id of this node (id = md5(public_key))
    std::string id;    
    std::string public_key;
    std::string private_key;
    char *data;
    unsigned long data_size;
    CELL_FLAGS flags;
    Dnp::System *system;

    struct cell_changes cell_changes;

private:
};
} // namespace Dnp
#endif