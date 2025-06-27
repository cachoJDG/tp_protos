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
#include "../stm.h"
#include "../users/users.h"

#define MAXPENDING 5 // Maximum outstanding connection requests
#define BUFSIZE 256
#define MAX_ADDR_BUFFER 128
#define SELECTOR_CAPACITY 256

static char addrBuffer[MAX_ADDR_BUFFER];

typedef struct ClientData {
    char buffer[BUFSIZE];
    ssize_t bytes;
    struct state_machine stm; // Pointer to the state machine for this client
    struct user {
        char username[64]; // Buffer for username
        char password[64]; // Buffer for password
    } user;
} ClientData;

struct sockaddr_storage _localAddr; // TODO: VARIABLE GLOBAL!!!!!
void client_handler_read(struct selector_key *key);
void client_handler_close(struct selector_key *key);

char username[64];  //TODO: ESTA MAL, SACAR.
char password[64];

void print_hex_compact(const char* label, const unsigned char* buffer, size_t length) {
    printf("%s (%zu bytes): ", label, length);
    for (size_t i = 0; i < length; i++) {
        printf("%02X", buffer[i]);
        if (i < length - 1) printf(" ");
    }
    printf("\n");
}


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


enum StateSocksv5 {
    STM_LOGIN_READ,
    STM_LOGIN_WRITE,
    STM_REQUEST_READ,
    STM_REQUEST_WRITE,
    STM_ERROR, // DEBE SER EL ULTIMO
};

void stm_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    memset(clientData->buffer, 0, BUFSIZE);
}

enum StateSocksv5 stm_login_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytes = recv(key->fd, clientData->buffer, BUFSIZE, 0);
    printf("String recibido: %b\n", clientData->buffer);
    print_hex_compact("Datos recibidos", (unsigned char*)clientData->buffer, bytes);
    char * message = clientData->buffer;

    /*

    char *username = strtok(clientData->buffer, "|");
    char *password = strtok(NULL, "|");

    if (username && password) {
        printf("Usuario: %s\n", username);
        printf("Contraseña: %s\n", password);
        if(validate_login(username, password)) {
            printf("Login exitoso\n");
        } else {
            printf("Login fallido\n");
            clientData->user.username[0] = '\0';
            clientData->user.password[0] = '\0';
            selector_set_interest_key(key, OP_NOOP); // Deshabilitar escritura
            return STM_ERROR; // O el estado que corresponda para manejar el error
        }
        strncpy(clientData->user.username, username, sizeof(clientData->user.username) - 1);
        clientData->user.username[sizeof(clientData->user.username) - 1] = '\0';
        strncpy(clientData->user.password, password, sizeof(clientData->user.password) - 1);
        clientData->user.password[sizeof(clientData->user.password) - 1] = '\0';
    } else {
        printf("Formato inválido\n");
        clientData->user.username[0] = '\0';
        clientData->user.password[0] = '\0';
    }
    */
    int index = 1;
    int usernameLength = message[index++];
    memcpy(username, message + index, usernameLength);
    username[usernameLength] = '\0'; // Null-terminate the username
    printf("Username: %s\n", username);
    printf("Username length: %d\n", usernameLength);
    index += usernameLength;
    int passwordLength = message[index++];
    memcpy(password, message + index, passwordLength);
    password[passwordLength] = '\0'; // Null-terminate the password
    printf("Password: %s\n", password);
    printf("Password length: %d\n", passwordLength);

    selector_set_interest_key(key, OP_WRITE); 
    return STM_LOGIN_WRITE;
}

enum StateSocksv5 stm_login_write(struct state_machine *stm, struct selector_key *key) {
    ClientData *clientData = key->data;

    if(validate_login(username, password)){
        char welcomeMessage[64];
        snprintf(welcomeMessage, sizeof(welcomeMessage), "Bienvenido al servidor, %s\n", username);
        printf("%s", welcomeMessage);
        send(key->fd, welcomeMessage, strlen(welcomeMessage), 0);
    }

    return STM_LOGIN_READ; // O el estado que corresponda
}

static const struct state_definition CLIENT_STATE_TABLE[] = {
    {
        .state = STM_LOGIN_READ,
        .on_arrival = stm_read_arrival,
        .on_read_ready = stm_login_read,
    },
    {
        .state = STM_LOGIN_WRITE,
        .on_write_ready = stm_login_write,
    }, 
    {
        .state = STM_REQUEST_READ,
        .on_arrival = stm_read_arrival,
        .on_read_ready = NULL, //CAMBIAR ESTO
    },
    {
        .state = STM_REQUEST_WRITE,
        .on_write_ready = NULL, //CAMBIAR ESTO
    }, 
    ///
        {
        .state = STM_ERROR, 
        .on_arrival = NULL, 
    },
};


void client_handler_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    enum StateSocksv5 state = stm_handler_read(&clientData->stm, key);
    if(state == STM_ERROR) {
        client_handler_close(key);
    }
    return;
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
    selector_set_interest_key(key, OP_NOOP); // quiza sacar esto
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
    
    clientData->stm.initial = STM_LOGIN_READ;
    clientData->stm.max_state = STM_ERROR;
    clientData->stm.states = CLIENT_STATE_TABLE;

    stm_init(&clientData->stm);

    selector_register(key->s, clientSocket, clientHandler, OP_READ, (void *)clientData);
}





int main(int argc, char *argv[]) {

    load_users(); // Carga los usuarios desde el archivo
    print_users();

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