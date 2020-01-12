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
#include "types.h"
typedef unsigned short DATA_HASH_SIZE;


namespace Dnp
{
struct rsa_keypair
{
    std::string pub_key;
    std::string private_key;
    std::string pub_key_md5_hash;
    std::string private_key_md5_hash;
};

struct DnpEncryptedHash
{
    char hash[MAX_RSA_ENCRYPTION_OUTPUT_SIZE];
    DATA_HASH_SIZE size;
};


class Rsa
{
public:
    Rsa();
    virtual ~Rsa();
    static void decrypt_public(const std::string &pub_key, const std::string &input, std::string &out);
    static void encrypt_private(const std::string &pri_key, const std::string &input, std::string &out);
    static std::string makeEncryptedHash(const std::string& input, const std::string& private_key);
    static void makeEncryptedHash(const std::string& input, const std::string& private_key, struct DnpEncryptedHash& out_hash);
    static struct rsa_keypair generateKeypair();
    
};
} // namespace Dnp

#endif