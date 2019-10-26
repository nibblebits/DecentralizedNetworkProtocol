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
    struct sockaddr_in servaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(DNP_FAMILY, SOCK_RAW, DNP_DATAGRAM_PROTOCOL)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = DNP_FAMILY;
    servaddr.sin_port = htons(PORT);
    memcpy(&servaddr.sin_addr.s_addr, "ffffffffffffffffffffffffffffffff", sizeof(servaddr.sin_addr.s_addr));

    int res = bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr));
    if (res < 0)
    {
        printf("Failed to bind! Size=: %i\n", (int)sizeof(servaddr));
        printf("%s\n", strerror(res));
    }

    while(1) {}
    //    int rc = sendto(sockfd, "Hello world", sizeof("Hello world"), 0, (struct sockaddr*) &servaddr.sin_family, sizeof(servaddr));
    //  printf("%i\n", rc);

    close(sockfd);
    return 0;
}