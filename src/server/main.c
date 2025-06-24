#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "../shared/logger.h"
#include "../shared/util.h"
#include "../selector.h"
#include <signal.h>
#include "map.h"

#define MAXPENDING 5 // Maximum outstanding connection requests
#define BUFSIZE 256
#define MAX_ADDR_BUFFER 128
#define SELECTOR_CAPACITY 256

static char addrBuffer[MAX_ADDR_BUFFER];

typedef struct ClientData {
    char buffer[BUFSIZE];
    ssize_t bytes;
} ClientData;

map hashmap = NULL; // Global hashmap to store user credentials
/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
int setupTCPServerSocket(const char *service) {
	// Construct the server address structure
	struct addrinfo addrCriteria;                   // Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;             // Any address family
	addrCriteria.ai_flags = AI_PASSIVE;             // Accept on any address/port
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only stream sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

	struct addrinfo *servAddr; 			// List of server addresses
	int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		log(FATAL, "getaddrinfo() failed %s", gai_strerror(rtnVal));
		return -1;
	}

	int servSock = -1;
	// Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio, sin especificar una IP en particular
	// Iteramos y hacemos el bind por alguna de ellas, la primera que funcione, ya sea la general para IPv4 (0.0.0.0) o IPv6 (::/0) .
	// Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
	for (struct addrinfo *addr = servAddr; addr != NULL && servSock == -1; addr = addr->ai_next) {
		errno = 0;
		// Create a TCP socket
		servSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (servSock < 0) {
			log(DEBUG, "Cant't create socket on %s : %s ", printAddressPort(addr, addrBuffer), strerror(errno));  
			continue;       // Socket creation failed; try next address
		}

		// Bind to ALL the address and set socket to listen
		if ((bind(servSock, addr->ai_addr, addr->ai_addrlen) == 0) && (listen(servSock, MAXPENDING) == 0)) {
			// Print local address of socket
			struct sockaddr_storage localAddr;
			socklen_t addrSize = sizeof(localAddr);
			if (getsockname(servSock, (struct sockaddr *) &localAddr, &addrSize) >= 0) {
				printSocketAddress((struct sockaddr *) &localAddr, addrBuffer);
				log(INFO, "Binding to %s", addrBuffer);
			}
		} else {
			log(DEBUG, "Cant't bind %s", strerror(errno));  
			close(servSock);  // Close and try with the next one
			servSock = -1;
		}
	}

	freeaddrinfo(servAddr);

	return servSock;
}

int acceptTCPConnection(int servSock) {
	struct sockaddr_storage clntAddr; // Client address
	// Set length of client address structure (in-out parameter)
	socklen_t clntAddrLen = sizeof(clntAddr);

	// Wait for a client to connect
	int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
	if (clntSock < 0) {
		log(ERROR, "accept() failed");
		return -1;
	}

	// clntSock is connected to a client!
	printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);
	log(INFO, "Handling client %s", addrBuffer);

	return clntSock;
}

void client_handler_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytes = recv(key->fd, clientData->buffer, BUFSIZ, 0);
    printf("CLIENT_READ[%d]='%s'\n", key->fd,clientData->buffer);
    int length = clientData->buffer[0];
    
    /// ---- Auth (Por ahora, no hay estados y lo único que hace el server es responder al pedido de login)

    // // TODO: Ver qué hacer con el null terminated
    // char clientName[64] ;
    // memcpy(&clientName, &clientData->buffer[1], clientData->buffer[0]);
    // char clientPassword[64];
    // int passwordLength = clientData->buffer[length + 1];
    // memcpy(&clientPassword, &clientData->buffer[length + 2], passwordLength);
    // clientName[length] = '\0'; // Null terminate the username
    // clientPassword[passwordLength] = '\0'; // Null terminate the username

    // printf("Username length: %d\n", length);
    // printf("Username: %s\n", clientName);
    // printf("Password length: %d\n", passwordLength);
    // printf("Password: %s\n", clientPassword);

    // printf("Map created with %d elements\n", map_size(hashmap));

    // //printf("Password from map: %s\n", (char *) map_get(hashmap, "john"));

    // if(map_contains(hashmap, clientName) == false) {
    //     printf("User %s not found\n", clientName);
    //     clientData->bytes = 0; // No response
    //     selector_set_interest_key(key, OP_NOOP);
    //     return;
    // }
    
    // char *password = map_get(hashmap, clientName);

    // if(strcmp(password, clientPassword) != 0) {
    //     printf("Wrong password for user %s\n", clientName);
    //     clientData->bytes = 0; // No response
    //     selector_set_interest_key(key, OP_NOOP);
    //     return;
    // }

    // printf("User %s authenticated successfully\n", clientName);

    /// ----- End Auth

    fd_interest newInterests = OP_WRITE;
    clientData->bytes = bytes;
    if (clientData->bytes < BUFSIZ)
        newInterests |= OP_READ;
    if(clientData->bytes == 0)
        newInterests = OP_NOOP;
    selector_set_interest_key(key, newInterests);
}

void client_handler_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    printf("CLIENT_WRITE[%d]='%s'\n", key->fd, clientData->buffer);
    send(key->fd, clientData->buffer, clientData->bytes, 0);
    selector_set_interest_key(key, OP_READ);
}
void client_handler_close(struct selector_key *key) {
    puts("handling client close");
    free(key->data);
    selector_set_interest_key(key, OP_NOOP);
}
void handle_read_passive(struct selector_key *key) {
    int clientSocket = acceptTCPConnection(key->fd);
    fd_handler *clientHandler = malloc(sizeof(fd_handler)); // TODO free
    clientHandler->handle_read = client_handler_read;
    clientHandler->handle_write = client_handler_write;
    clientHandler->handle_close = client_handler_close;
    ClientData *clientData = calloc(1, sizeof(ClientData)); 
    selector_register(key->s, clientSocket, clientHandler, OP_READ, (void *)clientData);
    // char buffer[BUFSIZE] = {0};
    // puts("handle read!!");
    // // ssize_t n = recv(key->fd, buffer, BUFSIZE, 0);
    // ssize_t n = recv(clientSock, buffer, BUFSIZE, 0);

    // if (n <= 0) {
    //     // cierre o error
    //     selector_unregister_fd(key->s, key->fd);
    //     close(key->fd);
    //     return;
    // }
    // send(clientSock, buffer, n, 0);
}

int main(int argc, char *argv[]) {

    hashmap = map_create();
    map_set(hashmap, "john", "doe");
    map_set(hashmap, "alex", "1234");
    if(map_contains(hashmap, "john") == true) {
        printf("User john is in the map\n");
    }
    printf("Map created with %d elements\n", map_size(hashmap));

    if (argc != 2) {
        log(FATAL, "usage: %s <Server Port>", argv[0]);
    }

    // 1) Preparo el socket de escucha
    int servSock = setupTCPServerSocket(argv[1]);
    if (servSock < 0) return 1;

    // 2) Pongo el socket en modo no-bloqueante
    if (selector_fd_set_nio(servSock) < 0) {
        log(FATAL, "Could not set O_NONBLOCK on listening socket");
    }

    // 3) Inicializo el selector
    const struct selector_init conf = {
        .signal = SIGALRM,          // o la señal que prefieras para notifs
        .select_timeout = { .tv_sec = 1, .tv_nsec = 0 }
    };
    selector_init(&conf);
    fd_selector selector = selector_new(SELECTOR_CAPACITY);

    // 4) Registro el socket de escucha en el selector
    //    Cuando haya OP_READ, invocará handle_listen()
    static const fd_handler listen_handler = {
        .handle_read  = handle_read_passive,   // en handle_read haces el accept()
        .handle_write = NULL,
        .handle_block = NULL,
        .handle_close = NULL
    };
    selector_register(selector, servSock, &listen_handler, OP_READ, NULL);

    // 5) Bucle principal: dejo que el selector gestione todos los eventos
    while (selector_select(selector) == SELECTOR_SUCCESS) {
        ; // selector_select internamente invoca tus callbacks
    }

    selector_destroy(selector);
	selector_close();
    return 0;
}
