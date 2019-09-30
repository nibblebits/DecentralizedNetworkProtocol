#ifndef MISC_H
#define MISC_H

#include <string>
std::string to_hex(const unsigned char* buf, int length);
std::string md5_hex(std::string str);
void map_data(std::string filename, off_t offset, size_t size, int& mmap_fd, void** mmap_data, size_t& mmap_size, char** data_ptr);
#endif