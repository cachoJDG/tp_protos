#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "../shared/logger.h"
#include "../shared/util.h"
#include "../selector.h"
#include "../parser.h"
#include <signal.h>
#include "map.h"
#include "../stm.h"

#define MAXPENDING 5 // Maximum outstanding connection requests
#define BUFSIZE 256
#define MAX_ADDR_BUFFER 128
#define SELECTOR_CAPACITY 256

static char addrBuffer[MAX_ADDR_BUFFER];

typedef struct ClientData {
    char buffer[BUFSIZE];
    ssize_t bytes;
    struct state_machine stm; // Pointer to the state machine for this client
} ClientData;
struct sockaddr_storage _localAddr; // TODO: VARIABLE GLOBAL!!!!!
map hashmap = NULL; // Global hashmap to store user credentials
void client_handler_read(struct selector_key *key);
void client_handler_close(struct selector_key *key);

enum StateSocksv5 {
    STM_INITIAL_READ,
    STM_INITIAL_WRITE,
    STM_LOGIN_READ,
    STM_LOGIN_WRITE,
    STM_REQUEST_READ,
    STM_REQUEST_WRITE,
    STM_REQUEST_CONNECT,
    STM_REQUEST_DNS,
    STM_ERROR, // DEBE SER EL ULTIMO
};

void stm_initial_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    memset(clientData->buffer, 0, sizeof(clientData->buffer));
}

enum StateSocksv5 stm_initial_read(struct selector_key *key) {
    ClientData *clientData = key->data; // TODO: validar si nos mandaron menos. ahora crashearia 

    ssize_t bytesRead = recv(key->fd, clientData->buffer, BUFSIZE, 0);
    if(bytesRead <= 0) {
        return STM_ERROR;
    }

    print_hex(clientData->buffer, bytesRead);
    int index = 0;
    int version = clientData->buffer[index++];
    int methodCount = clientData->buffer[index++];
    printf("version=%d methodCount=%d [", version, methodCount);
    for(int i = 0; i < methodCount; i++) {
        printf("%d, ", clientData->buffer[index++]);
    }
    puts("]");

    selector_set_interest_key(key, OP_WRITE); 

    return STM_INITIAL_WRITE;
}

enum StateSocksv5 stm_initial_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    
    char message[BUFSIZE] = {0};
    message[0] = SOCKS_PROTOCOL_VERSION;
    message[1] = 0x02; // LOGIN
    ssize_t bytes = send(key->fd, message, 2, 0);
    selector_set_interest_key(key, OP_READ); 
    return STM_LOGIN_READ;

    // TODO: este es el caso de que el cliente haya seleccionado METHOD=NONE=0x00
    // return STM_REQUEST_READ;
}

void stm_login_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    memset(clientData->buffer, 0, BUFSIZE);
}

enum StateSocksv5 stm_login_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    char message[BUFSIZE] = {0};
    ssize_t bytes = recv(key->fd, clientData->buffer, BUFSIZE, 0);
    print_hex(clientData->buffer, bytes);
    int index = 1;
    int usernameLen = clientData->buffer[index++];
    memcpy(message, &clientData->buffer[index], usernameLen);
    message[usernameLen] = '\0';
    printf("username[%d]: '%s'\n", usernameLen, message);
    index += usernameLen;
    int passwordLen = clientData->buffer[index++];
    memcpy(message, &clientData->buffer[index], passwordLen);
    message[passwordLen] = '\0';
    printf("password[%d]: '%s'\n", passwordLen, message);

    selector_set_interest_key(key, OP_WRITE); 
    return STM_LOGIN_WRITE;
}

enum StateSocksv5 stm_login_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    
    char message[2];
    message[0] = SOCKS_PROTOCOL_VERSION;
    message[1] = 0x00; // LOGIN_SUCCESS
    ssize_t bytes = send(key->fd, message, 2, 0);

    selector_set_interest_key(key, OP_READ); 
    return STM_REQUEST_READ;
}

void stm_request_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    memset(clientData->buffer, 0, BUFSIZE);
}

enum StateSocksv5 stm_request_read(struct selector_key *key) { // TODO: este de aca tiene MUCHA funcionalidad por hacer.
    ClientData *clientData = key->data;

    printf("after log: ");
    ssize_t bytes = recv(key->fd, clientData->buffer, BUFSIZE, 0);
    print_hex(clientData->buffer, bytes);
    int index = 1;
    int cmd = clientData->buffer[index++];
    //  cmd ENUM
    // CONNECT = 0x01,
    // BIND = 0x02,
    // UDP_ASSOCIATE = 0x03,
    
    int reserved = clientData->buffer[index++]; // TODO: QUIZA CHEQUEAR QUE VALGA 0x00
    int addressType = clientData->buffer[index++]; 
    //  addressType ENUM
    // ADDRESS_TYPE_IPV4 = 0x01, // LEER 4 BYTES
    // ADDRESS_TYPE_DOMAIN_NAME = 0x03, // LEER N BYTES
    // ADDRESS_TYPE_IPV6 = 0x04, // LEER 
    
    index += 4; // asume ipv4
    print_hex(&clientData->buffer[index], 2);
    uint16_t destinationPort = ntohs(*(uint16_t *)&clientData->buffer[index]);
    index += 2;
    printf("cmd=%d addressType=%d destinationAdress= destinationPort=%u\n", cmd, addressType, destinationPort);

    selector_set_interest_key(key, OP_WRITE); 
    return STM_REQUEST_WRITE;
}

enum StateSocksv5 stm_request_write(struct selector_key *key) {
    ClientData *clientData = key->data; 

    char message[BUFSIZE] = {0};
    struct sockaddr_in *local = (struct sockaddr_in*) &_localAddr;
    int index = 0;
    message[index++] = SOCKS_PROTOCOL_VERSION;
    message[index++] = 0x00; // REPLY == 0x00 es que lo acepta
    message[index++] = 0x00; // RESERVED debe valer 0x00
    message[index++] = 0x01; // ADDRESS TYPE = 0x01 -> IPV4
    memcpy(&message[index], &local->sin_addr, 4);
    index += 4;
    memcpy(&message[index], &local->sin_port, 2);
    index += 2;
    ssize_t bytes = send(key->fd, message, index, 0);

    selector_set_interest_key(key, OP_READ);
    
    return STM_ERROR; // TODO: cambiarlo por el estado correcto
}

void stm_error(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data; 
    ssize_t bytes = recv(key->fd, clientData->buffer, BUFSIZE, 0);
    printf("[ERROR] bytes recibidos: ");
    print_hex(clientData->buffer, bytes);
}

static const struct state_definition CLIENT_STATE_TABLE[] = {
    {
        .state = STM_INITIAL_READ, // https://datatracker.ietf.org/doc/html/rfc1928#section-3
        .on_arrival = stm_initial_read_arrival,
        .on_read_ready = stm_initial_read,
    },
    {
        .state = STM_INITIAL_WRITE,
        .on_write_ready = stm_initial_write,
    }, 
    {
        .state = STM_LOGIN_READ, // https://datatracker.ietf.org/doc/html/rfc1929
        .on_arrival = stm_login_read_arrival,
        .on_read_ready = stm_login_read,
    },
    {
        .state = STM_LOGIN_WRITE,
        .on_write_ready= stm_login_write,
    },
    {
        .state = STM_REQUEST_READ, // https://datatracker.ietf.org/doc/html/rfc1928#section-4
        .on_arrival = stm_request_read_arrival,
        .on_read_ready = stm_request_read,
    },
    {
        .state = STM_REQUEST_WRITE, // https://datatracker.ietf.org/doc/html/rfc1928#section-4
        .on_write_ready = stm_request_write,
    },
    {
        .state = STM_REQUEST_CONNECT, // https://datatracker.ietf.org/doc/html/rfc1928#section-4
        .on_arrival = NULL, // TODO
        .on_write_ready = NULL,
    },
    {
        .state = STM_REQUEST_DNS, 
        .on_write_ready = NULL, // TODO
    },
    ///
        {
        .state = STM_ERROR, 
        .on_arrival = stm_error, 
    },
};

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
                _localAddr = localAddr;
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
    enum StateSocksv5 state = stm_handler_read(&clientData->stm, key);
    if(state == STM_ERROR) {
        client_handler_close(key);
    }
    return;
    //

    /*

    //

    
    //


    //


    //


    //
    bytes = recv(key->fd, clientData->buffer, BUFSIZE, 0);
    print_hex(clientData->buffer, bytes);
    exit(0);
        */
    /// ---- Auth (Por ahora, no hay estados y lo único que hace el server es responder al pedido de login)
    // int usernameLength = clientData->buffer[1];

    // TODO: Ver qué hacer con el null terminated
    // char clientName[64] ;
    // memcpy(clientName, &clientData->buffer[2], usernameLength);
    // clientName[usernameLength] = '\0'; // Null terminate the username

    // int passwordLength = clientData->buffer[usernameLength + 2];

    // char clientPassword[64];
    // memcpy(clientPassword, &clientData->buffer[usernameLength + 3], passwordLength);
    // clientPassword[passwordLength] = '\0'; // Null terminate the username

    // printf("Username length: %d\n", usernameLength);
    // printf("Username: %s\n", clientName);
    // printf("Password length: %d\n", passwordLength);
    // printf("Password: %s\n", clientPassword);


    // if(map_contains(hashmap, clientName) == false) {
    //     printf("User %s not found\n", clientName);
    //     clientData->bytes = 0; // No response
    //     selector_set_interest_key(key, OP_NOOP);
    //     return;
    // }

    // printf("User %s authenticated successfully\n", clientName);

    /// ----- End Auth

    // fd_interest newInterests = OP_WRITE;
    // clientData->bytes = bytes;
    // if (clientData->bytes < BUFSIZ)
    //     newInterests |= OP_READ;
    // if(clientData->bytes == 0)
    //     newInterests = OP_NOOP;
    // selector_set_interest_key(key, newInterests);
}

void client_handler_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    enum StateSocksv5 state = stm_handler_write(&clientData->stm, key);
    if(state == STM_ERROR) {
        client_handler_close(key);
    }
}
void client_handler_block(struct selector_key *key) {
    ClientData *clientData = key->data;
    enum StateSocksv5 state = stm_handler_block(&clientData->stm, key);
    if(state == STM_ERROR) {
        client_handler_close(key);
    }
}
void client_handler_close(struct selector_key *key) {
    ClientData *clientData = key->data;
    // enum StateSocksv5 state = stm_handler_close(&clientData->stm, key); // este no retorna xd
    // TODO: avoid double free
    selector_set_interest_key(key, OP_NOOP); // quiza sacar esto
    // selector_unregister_fd(key->s, key->s);
    puts("handling client close");
    free(key->data);
}
void handle_read_passive(struct selector_key *key) {
    int clientSocket = acceptTCPConnection(key->fd);
    fd_handler *clientHandler = malloc(sizeof(fd_handler)); // TODO free
    clientHandler->handle_read = client_handler_read;
    clientHandler->handle_write = client_handler_write;
    clientHandler->handle_close = client_handler_close;
    clientHandler->handle_block = client_handler_block;
    ClientData *clientData = calloc(1, sizeof(ClientData)); 
    
    clientData->stm.initial = STM_INITIAL_READ;
    clientData->stm.max_state = STM_ERROR;
    clientData->stm.states = CLIENT_STATE_TABLE;

    stm_init(&clientData->stm);

    selector_register(key->s, clientSocket, clientHandler, OP_READ, (void *)clientData);
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

// unsigned stm_state_initial_handler(struct selector_key* key) {
//     ClientData *clientData = key->data;
//     // ssize_t bytes = recv(key->fd, clientData->buffer, BUFSIZ, 0);
//     // printf("CLIENT_READ[%d]='%s'\n", key->fd,clientData->buffer);
//     int usernameLength = clientData->buffer[1];
    
//     /// ---- Auth (Por ahora, no hay estados y lo único que hace el server es responder al pedido de login)

//     // TODO: Ver qué hacer con el null terminated
//     char clientName[64] ;
//     memcpy(clientName, &clientData->buffer[2], usernameLength);
//     clientName[usernameLength] = '\0'; // Null terminate the username

//     int passwordLength = clientData->buffer[usernameLength + 2];

//     char clientPassword[64];
//     memcpy(clientPassword, &clientData->buffer[usernameLength + 3], passwordLength);
//     clientPassword[passwordLength] = '\0'; // Null terminate the username

//     printf("Username length: %d\n", usernameLength);
//     printf("Username: %s\n", clientName);
//     printf("Password length: %d\n", passwordLength);
//     printf("Password: %s\n", clientPassword);


//     if(map_contains(hashmap, clientName) == false) {
//         printf("User %s not found\n", clientName);
//         clientData->bytes = 0; // No response
//         selector_set_interest_key(key, OP_NOOP);
//         return;
//     }

//     printf("User %s authenticated successfully\n", clientName);

//     /// ----- End Auth

//     fd_interest newInterests = OP_WRITE;
//     clientData->bytes = bytes;
//     if (clientData->bytes < BUFSIZ)
//         newInterests |= OP_READ;
//     if(clientData->bytes == 0)
//         newInterests = OP_NOOP;
//     selector_set_interest_key(key, newInterests);
// }