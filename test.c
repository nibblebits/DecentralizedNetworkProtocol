#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
  
#define PORT     8080 
#define MAXLINE 1024 
#define DNP_FAMILY 43
#define DNP_DATAGRAM_PROTOCOL 0
#define DNP_MAX_PROTOCOLS 1
#define DNP_MAX_OPTIONS 4

#define SOCKET_OPTION_VALUE_INTEGER 0
#define SOCKET_OPTION_VALUE_BUFFER 1
typedef int SOCKET_OPTION_VALUE_TYPE;

#define DNP_SOCKET_OPTION_MUST_DELIVER 0
#define DNP_SOCKET_MUST_DELIVER 1
#define DNP_SOCKET_NO_DELIVERY_ACCEPTABLE 0
  
// Driver code 
int main() { 
    int sockfd; 
    char buffer[MAXLINE]; 
    char *hello = "Hello from client"; 
    struct sockaddr_in     servaddr; 
  
   // Creating socket file descriptor 
    if ( (sockfd = socket(DNP_FAMILY, SOCK_RAW, DNP_DATAGRAM_PROTOCOL)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 

    int a = DNP_SOCKET_MUST_DELIVER;
    setsockopt(sockfd, 0, DNP_SOCKET_OPTION_MUST_DELIVER, &a, sizeof(a));
    send(sockfd, "Hello world", 5, 0);
    
  
    close(sockfd); 
    return 0; 
} 