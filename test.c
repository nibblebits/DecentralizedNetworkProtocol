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
    struct dnp_address cliaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(DNP_FAMILY, SOCK_RAW, DNP_DATAGRAM_PROTOCOL)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    char addr[DNP_ID_SIZE+1];
    memcpy(addr, "42614bd2ef87371f282b8e500f9c0428", sizeof(addr));
    addr[DNP_ID_SIZE] = 0;
    // Filling server information
    servaddr.port = htons(PORT);
    servaddr.addr = addr;
    //servaddr.flags = DNP_ADDRESS_FLAG_GENERATE_ADDRESS;
    int res = bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (res < 0)
    {
        printf("Failed to bind! Size=: %i\n", (int)sizeof(servaddr));
        printf("%s\n", strerror(res));
    }
    
    cliaddr.port = htons(PORT);
    cliaddr.addr = addr;
    addr[0] = 'E';

    printf("%s\n", addr);

    int rc = sendto(sockfd, "Hello world", sizeof("Hello world"), 0, (struct sockaddr*) &cliaddr, sizeof(cliaddr));
    if (rc < 0)
    {
        printf("Failed to send packet\n");
        printf("%s\n", strerror(rc));
    }

    //    int rc = sendto(sockfd, "Hello world", sizeof("Hello world"), 0, (struct sockaddr*) &servaddr.sin_family, sizeof(servaddr));
    //  printf("%i\n", rc);
    close(sockfd);
    return 0;
}