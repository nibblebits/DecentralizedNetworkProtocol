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

/**
 * This file is a simple C++ RSA wrapper that wraps over OpenSSL RSA
 */
#ifndef RSA_H
#define RSA_H

#include <string>
namespace Dnp
{
    struct rsa_keypair
    {
        std::string pub_key;
        std::string private_key;
        std::string pub_key_md5_hash;
        std::string private_key_md5_hash;
    };

    class Rsa
    {
        public:
            Rsa();
            virtual ~Rsa();

            static struct rsa_keypair generateKeypair();
    };
}

#endif