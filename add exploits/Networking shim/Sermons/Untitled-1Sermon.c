#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

static struct sockaddr_in derive_sockaddr(const char* host, const char* port){
    struct addrinfo hints = {
        .ai_family = AF_INET,
    };
    struct addrinfo *result_info;

    // Resolve the host (IP address or hostname) into a list of possible addresses.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode) {
        fprintf(stderr, "Error parsing host/port");
        exit(EXIT_FAILURE);
    }

    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in*) result_info->ai_addr);

    // Free the allocated memory for the result_info
    freeaddrinfo(result_info);
    return result;
}
int main(int argc, char *argv[]) {

    if (argc != 3) {
        return 1;
    }
    const char *host = argv[1];
    const char *port = argv[2];

    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    int optval = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in new_server_address = derive_sockaddr(host, port);

    bind(s, (struct sockaddr*)&new_server_address, sizeof(new_server_address));
    listen(s,20);


    return 0;
}