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

enum {
	LIST_USERS = 1,
	ADD_USER = 2,
	REMOVE_USER = 3,
	CHANGE_PASSWORD = 4
}Commands;

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

void sendCommand(int clientSocket, char ** commands){

	if(strcmp(commands[0], "LIST") == 0 && strcmp(commands[1], "USERS") == 0) {
		unsigned char msg = LIST_USERS;
		send(clientSocket, &msg, 1, 0); // SOCKS5 LIST USERS command
	}
	else if(strcmp(commands[0], "ADD") == 0 && strcmp(commands[1], "USER") == 0) {
		char ans[BUFSIZE] = {0};
		if (commands[2] == NULL || commands[3] == NULL) {
			fprintf(stderr, "Usage: ADD USER <username> <password>\n");
			return;
		}
		ans[0] = ADD_USER;
		int index = 1;
		int usernameLength = strlen(commands[2]);
		ans[index++] = usernameLength;
		memcpy(ans + index, commands[2], usernameLength);
		index += usernameLength;
		int passwordLength = strlen(commands[3]);
		ans[index++] = passwordLength;
		memcpy(ans + index, commands[3], passwordLength);
		index += passwordLength;
		send(clientSocket, ans, index, 0);
	}
	else {
		fprintf(stderr, "Unknown command\n");
	}
}

bool authClient(int clientSocket) {

	char* token = getenv("TOKEN");
	if (token == NULL) {
		fprintf(stderr, "No token provided for connection\n");
		return -1;
	}
	
	char *clientName = strtok(token, "|");
	char *clientPassword = strtok(NULL, "|");

	if (clientName == NULL || clientPassword == NULL) {
		fprintf(stderr, "Client error: invalid token format\n");
		return false;
	}

	if (strlen(clientName) > 255 || strlen(clientPassword) > 255) {
		fprintf(stderr, "Client error: client name or password too long\n");
		return false;
	}

    char message[BUFSIZE] = { 0 }; // TODO: verificar que clientName y clientPassword no excedan. BUFFER OVERFLOW
    size_t index = 0;
    message[index++] = SOCK_VERSION;

    size_t clientNameLength = strlen(clientName);
    message[index++] = clientNameLength;
    memcpy(message + index, clientName, clientNameLength);
    index += clientNameLength;

    size_t clientPasswordLength = strlen(clientPassword);
    message[index++] = clientPasswordLength;
    memcpy(message + index, clientPassword, clientPasswordLength);
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

void loadFileUsers(){
	FILE *f = fopen("users.txt", "r");
	if (f == NULL) {
		fprintf(stderr, "Error opening users file: %s\n", strerror(errno));
		return;
	}

	char line[128];
	while (fgets(line, sizeof(line), f)) {
		char *username = strtok(line, ";");
		char *password = strtok(NULL, ";");
		if (username && password) {
			printf("Usuario: %s, Contraseña: %s\n", username, password);
		}
	}
	fclose(f);
}

void readServerResponse(int clientSocket) {
    char buffer[BUFSIZE];
    ssize_t bytesReceived;
    
    bytesReceived = recv(clientSocket, buffer, BUFSIZE - 1, 0);
    
    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0'; // Null-terminate
        printf("%s", buffer);
    } else if (bytesReceived == 0) {
        printf("El servidor cerró la conexión\n");
    } else {
        perror("Error al recibir respuesta del servidor");
    }
}

int main(int argc, char *argv[]) {

	/*if (argc != 4) {
		log(FATAL, "usage: %s <Server Name/Address> <Echo Word> <Server Port/Name>", argv[0]);
	}*/

	char *server = argv[1];     // First arg: server name IP address 

	// Third arg server port
	char * port = argv[2];

	// Create a reliable, stream socket using TCP
	int clientSocket = tcpClientSocket(server, port);
	if (clientSocket < 0) {
		log(FATAL, "socket() failed")
	}
    bool authSuccess = authClient(clientSocket);

	char *commands[argc - 3];
	for(int i = 3; i < argc; i++) {
		commands[i - 3] = argv[i];
	}
	sendCommand(clientSocket ,commands);

	readServerResponse(clientSocket);

	close(clientSocket);
	return 0;
}
