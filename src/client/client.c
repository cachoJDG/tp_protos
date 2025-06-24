#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "../shared/logger.h" 
#include "../shared/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>

#define MAX_ADDR_BUFFER 128
#define BUFSIZE 512
#define SOCK_VERSION 5

int tcpClientSocket(const char *host, const char *service) {
	char addrBuffer[MAX_ADDR_BUFFER] = {0};
	struct addrinfo addrCriteria;                   // Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;             // v4 or v6 is OK
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only streaming sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

	// Get address(es)
	struct addrinfo *servAddr; // Holder for returned list of server addrs
	int rtnVal = getaddrinfo(host, service, &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		log(ERROR, "getaddrinfo() failed %s", gai_strerror(rtnVal))
		return -1;
	}

	int sock = -1;
	for (struct addrinfo *addr = servAddr; addr != NULL && sock == -1; addr = addr->ai_next) {
		// Create a reliable, stream socket using TCP
		sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (sock >= 0) {
			errno = 0;
			// Establish the connection to the server
			if (connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
				log(INFO, "can't connectto %s: %s", printAddressPort(addr, addrBuffer), strerror(errno))
				close(sock); 	// Socket connection failed; try next address
				sock = -1;
			}
		} else {
			log(DEBUG, "Can't create client socket on %s",printAddressPort(addr, addrBuffer)) 
		}
	}

	freeaddrinfo(servAddr); 
	return sock;
}

bool authClient(int clientSocket, char *clientName, char *clientPassword) {
	// TODO: sacarle el null terminated a los strings, ya que no se envían al servidor
    char message[BUFSIZE] = { 0 }; // TODO: verificar que clientName y clientPassword no excedan. BUFFER OVERFLOW
    size_t index = 0;
    message[index++] = SOCK_VERSION;

    size_t clientNameLength = strlen(clientName);
    message[index++] = clientNameLength;
    memcpy(&message[index], clientName, clientNameLength);
    index += clientNameLength;

    size_t clientPasswordLength = strlen(clientPassword);
    message[index++] = clientPasswordLength;
    memcpy(&message[index], clientPassword, clientPasswordLength);
    index += clientPasswordLength;

    if(send(clientSocket, message, index, 0) <= ERROR_VALUE) {
        fprintf(stderr, "Client error in first message");

        return false;
    }

    if(read(clientSocket, message, 2) < 1) {
        fprintf(stderr, "Client error");

        return false;
    }

    if(message[1] == 0) {
        fprintf(stderr, "Client error: incorrect password");

        return false;
    }

    return true;
}

int main(int argc, char *argv[]) {

	if (argc != 4) {
		log(FATAL, "usage: %s <Server Name/Address> <Echo Word> <Server Port/Name>", argv[0]);
	}

	char *server = argv[1];     // First arg: server name IP address 

	// Third arg server port
	char * port = argv[2];

	// Create a reliable, stream socket using TCP
	int clientSocket = tcpClientSocket(server, port);
	if (clientSocket < 0) {
		log(FATAL, "socket() failed")
	}
    bool authSuccess = authClient(clientSocket, "john", "doe");
    printf("Client[%d]: %d\n", clientSocket, authSuccess);
	// size_t echoStringLen = strlen(echoString); // Determine input length

	// // Send the string to the server
	// ssize_t numBytes = send(sock, echoString, echoStringLen, 0);
	// if (numBytes < 0 || numBytes != echoStringLen)
	// 	log(FATAL, "send() failed expected %zu sent %zu", echoStringLen, numBytes);

	// // Receive the same string back from the server
	// unsigned int totalBytesRcvd = 0; // Count of total bytes received
	// log(INFO, "Received: ")     // Setup to print the echoed string
	// while (totalBytesRcvd < echoStringLen && numBytes >=0) {
	// 	char buffer[BUFSIZE]; 
	// 	/* Receive up to the buffer size (minus 1 to leave space for a null terminator) bytes from the sender */
	// 	numBytes = recv(sock, buffer, BUFSIZE - 1, 0);
	// 	if (numBytes < 0) {
	// 		log(ERROR, "recv() failed")
	// 	}  
	// 	else if (numBytes == 0)
	// 		log(ERROR, "recv() connection closed prematurely")
	// 	else {
	// 		totalBytesRcvd += numBytes; // Keep tally of total bytes
	// 		buffer[numBytes] = '\0';    // Terminate the string!
	// 		log(INFO, "%s", buffer);      // Print the echo buffer
	// 	}
	// }

	close(clientSocket);
	return 0;
}
