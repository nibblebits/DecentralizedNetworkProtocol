#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "dnpmodshared.h"

#define PORT 8080
#define MAXLINE 1024

// Driver code
int main()
{
    int sockfd;
    char buffer[MAXLINE];
    char *hello = "Hello from client";
    

    struct dnp_address servaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(DNP_FAMILY, SOCK_RAW, DNP_DATAGRAM_PROTOCOL)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    memset(&servaddr, 0, sizeof(servaddr));

    char addr[DNP_ID_SIZE];
    memcpy(addr, "1491f2c8c1c3fb3286869b47bd3d6b68", sizeof(addr));

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
    
   int rc = sendto(sockfd, "Hello world", sizeof("Hello world"), 0, (struct sockaddr*) &servaddr, sizeof(servaddr));
    if (rc < 0)
    {
        printf("Failed to send packet\n");
        printf("%s\n", strerror(rc));
    }

    while(1) {}
    //    int rc = sendto(sockfd, "Hello world", sizeof("Hello world"), 0, (struct sockaddr*) &servaddr.sin_family, sizeof(servaddr));
    //  printf("%i\n", rc);
    close(sockfd);
    return 0;
}