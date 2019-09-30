#include "misc.h"
#include "config.h"
#include <sstream>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdexcept>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/md5.h>

std::string to_hex(const unsigned char *buf, int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++)
    {
        ss << std::hex << (unsigned int)buf[i];
    }

    return ss.str();
}

std::string md5_hex(std::string str)
{
    unsigned char md5_out[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)str.c_str(), str.size(), md5_out);
    return to_hex(md5_out, MD5_DIGEST_LENGTH);
}

void map_data(std::string filename, off_t offset, size_t size, int &mmap_fd, void **mmap_data, size_t &mmap_size, char **data_ptr)
{
    int page_size = getpagesize();
    if (offset < page_size)
        throw std::logic_error("setMappedData() we expect the offset to at least be one page: " + page_size);

    size_t offset_misalignment = offset % page_size;
    off_t page_offset = offset - offset_misalignment;
    mmap_size = size + offset_misalignment;
    mmap_fd = open(filename.c_str(), O_RDONLY);
    *mmap_data = mmap(0, mmap_size, PROT_READ, MAP_PRIVATE, mmap_fd, page_offset);

    if (*mmap_data == MAP_FAILED)
    {
        throw std::logic_error("setMappedData() mmap failed sorry: " + std::string(strerror(errno)));
    }

    // As mmap data may not be pointing at correct offset let's readjust it for the actual data pointer
    *data_ptr = (char *)((char *)*mmap_data + offset_misalignment);
}