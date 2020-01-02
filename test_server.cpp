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

#define PORT 8080
#define MAXLINE 1024

// Driver code
int main()
{
    int sockfd;
    
    struct dnp_address servaddr;
    // Creating socket file descriptor
    if ((sockfd = socket(DNP_FAMILY, SOCK_RAW, DNP_DATAGRAM_PROTOCOL)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    memset(&servaddr, 0, sizeof(servaddr));

    char addr[DNP_ID_SIZE];
    memcpy(addr, "97944f7356d76126fd0329dfcf9461d6", DNP_ID_SIZE);


    // Filling server information
    servaddr.port = htons(PORT);
    servaddr.addr = addr;
    servaddr.flags = DNP_ADDRESS_FLAG_GENERATE_ADDRESS;
    int res = bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (res < 0)
    {
        printf("Failed to bind! Size=: %i\n", (int)sizeof(servaddr));
        printf("%s\n", strerror(res));
    }
    

    std::cout << "Generated address: " << std::string(addr, DNP_ID_SIZE) << " please send packet" << std::endl;
    struct dnp_address_in in_addr;
    memset(&in_addr, 0, sizeof(in_addr));
    
    char buf[512];
    socklen_t len = sizeof(in_addr);
    int rc = recvfrom(sockfd, &buf, sizeof(buf), DNP_WAIT, (struct sockaddr*) &in_addr, &len);
    if (rc < 0)
    {
        std::cout << "recv failed: " << strerror(rc) << std::endl;
    }

    std::cout << "Message: " << std::string(buf, len) << std::endl;

    close(sockfd);
    return 0;
}