#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <iostream>
#include <string>
#include "dnpmodshared.h"

#define PORT 8078
#define MAXLINE 1024

// Driver code
int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::cout << "Expecting a destination address" << std::endl;
        return -1;
    }


    std::string dst_address = std::string(argv[1]); 
    if (dst_address.size() != DNP_ID_SIZE)
    {
        std::cout << "Invalid destination address" << std::endl;
        return -1;
    }

    int sockfd;

    // Creating socket file descriptor
    if ((sockfd = socket(DNP_FAMILY, SOCK_RAW, DNP_DATAGRAM_PROTOCOL)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Temporary storage for addresses
    char addr[DNP_ID_SIZE];
    struct dnp_address our_addr;
    our_addr.port = htons(PORT);
    our_addr.addr = addr;
    our_addr.flags = DNP_ADDRESS_FLAG_GENERATE_ADDRESS;
    int res = bind(sockfd, (struct sockaddr *)&our_addr, sizeof(our_addr));
    if (res < 0)
    {
        printf("Failed to bind! Size=: %i\n", (int)sizeof(our_addr));
        printf("%s\n", strerror(res));
    }
    
    std::cout << "Our address: " << std::string(addr, DNP_ID_SIZE) << std::endl;

    // Destination information
    memcpy(addr, dst_address.c_str(), DNP_ID_SIZE);
    struct dnp_address cliaddr;
    cliaddr.port = htons(8080);
    cliaddr.addr = addr;
    cliaddr.flags = 0;
    int rc = 0;
    
    rc = sendto(sockfd, "Hello world!", sizeof("Hello world!"), 0, (struct sockaddr*) &cliaddr, sizeof(cliaddr));
    if (rc < 0)
    {
        std::cout << "Error sending: " << strerror(rc) << std::endl;
    }


    return 0;
}