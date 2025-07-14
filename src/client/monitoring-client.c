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
#include "clientCmdParser.h"
#include "clientCmdUtils.h"
#include "monitoring-client.h"

int tcpClientSocket(const char *host, const char *service) {
	char addrBuffer[MAX_ADDR_BUFFER_MONITORING] = {0};
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

void sendCommand(int clientSocket, char ** commands, int commandCount) {

	if(parseListUsersCommand(commands, commandCount)) {
		sendListUsersCommand(clientSocket);
	}
	else if(parseAddUserCommand(commands, commandCount)) {
		if(sendAddUserCommand(clientSocket ,commands) == -1){
			fprintf(stderr, "Error sending ADD USER command\n");
			close(clientSocket);
			free(commands);
			exit(1);
		}
	}
	else if(parseRemoveUserCommand(commands, commandCount)) {
		if(sendRemoveUserCommand(clientSocket ,commands) == -1){
			fprintf(stderr, "Error sending REMOVE USER command\n");
			close(clientSocket);
			free(commands);
			exit(1);
		}
	}
	else if(parseChangePasswordCommand(commands, commandCount)) {
		if(sendChangePasswordCommand(clientSocket ,commands) == -1){
			fprintf(stderr, "Error sending CHANGE PASSWORD command\n");
			close(clientSocket);
			free(commands);
			exit(1);
		}
	}
	else if(parseGetMetricsCommand(commands, commandCount)) {
		sendGetMetricsCommand(clientSocket);
	}
	else if(parseChangeRoleCommand(commands, commandCount)) {
		if(sendChangeRoleCommand(clientSocket ,commands) == -1){
			fprintf(stderr, "Error sending CHANGE ROLE command\n");
			close(clientSocket);
			free(commands);
			exit(1);
		}
	}
	else {
		fprintf(stderr, "Unknown command\nSome examples:\nLIST USERS\nADD USER <username> <password>\nREMOVE USER <username>\nCHANGE PASSWORD <username> <newpassword>\nCHANGE ROLE <username> <role>\nGET METRICS\n");
		close(clientSocket);
		free(commands);
		exit(1);
	}
}

bool authClient(int clientSocket) {

	char* token = getenv("MONITORING_TOKEN");
	if (token == NULL) {
		fprintf(stderr, "No token provided for connection\n");
		return -1;
	}
	
	char *clientName = strtok(token, ":");
	char *clientPassword = strtok(NULL, ":");

	if (clientName == NULL || clientPassword == NULL) {
		fprintf(stderr, "Client error: invalid token format\n");
		return false;
	}

	if (strlen(clientName) > UNAME_MAX_LENGTH || strlen(clientPassword) > PASSWORD_MAX_LENGTH) {
		fprintf(stderr, "Client error: client name or password too long\n");
		return false;
	}

    char message[BUFSIZE_MONITORING] = { 0 };
    size_t index = 0;
    message[index++] = MONITORING_VERSION;

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
        fprintf(stderr, "Client error: incorrect password\n");
        return false;
    }

    return true;
}

void readServerResponse(int clientSocket) {
    char buffer[BUFSIZE_COMMAND_MONITORING] = {0}; // Buffer para la respuesta del servidor
    int bytesRead;
    
    // Leer los primeros 2 bytes para obtener la longitud
    bytesRead = read(clientSocket, buffer, 2);
    if (bytesRead <= 0) {
        if (bytesRead == 0) {
            fprintf(stderr, "El servidor cerró la conexión\n");
        } else {
            perror("Error al leer del socket");
        }
        return;
    }
    
    // Convertir de network byte order (big endian) a host byte order
    uint32_t bytesToRead;
    memcpy(&bytesToRead, buffer, 2);
    bytesToRead = ntohs(bytesToRead);  // Network to Host Short
    
    // Leer el resto del mensaje
    bytesRead = read(clientSocket, buffer + 2, bytesToRead);
    if (bytesRead <= 0) {
        if (bytesRead == 0) {
            fprintf(stderr, "El servidor cerró la conexión\n");
        } else {
            perror("Error al leer del socket");
        }
        return;
    }
    
    if (bytesToRead > 0) {
        buffer[bytesToRead + 2] = '\0'; // Null-terminate
        printf("%s", buffer + 2);
    } else if (bytesToRead == 0) {
        printf("Respuesta vacía del servidor\n");
    }
}

int main(int argc, char *argv[]) {

	if (argc < 3) {
        fprintf(stderr, "Usage: %s <port> <command> [args...]\n", argv[0]);
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  %s 2020 LIST USERS\n", argv[0]);
        fprintf(stderr, "  %s 2020 ADD USER username password\n", argv[0]);
        return 1;
    }
	
	char *server = LOCALHOST; 

	// Second arg server port
	char *port = argv[1];

	// Create a reliable, stream socket using TCP
	int clientSocket = tcpClientSocket(server, port);
	if (clientSocket < 0) {
		log(FATAL, "socket() failed %d", clientSocket);
		return 1;
	}
    bool authSuccess = authClient(clientSocket);
	if(!authSuccess) {
		fprintf(stderr, "user auth failed\n");
		return 1;
	}
	int commandCount = argc - 2;
    char **commands = malloc(commandCount * sizeof(char*));
    if (commands == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        close(clientSocket);
        return 1;
    }

	for (int i = 0; i < commandCount; i++) {
        commands[i] = NULL;
    }

    for (int i = 2; i < argc; i++) {
        commands[i - 2] = argv[i];
    }

	sendCommand(clientSocket ,commands, argc - 2);

	readServerResponse(clientSocket);

	close(clientSocket);
	free(commands);
	return 0;
}
