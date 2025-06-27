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
#include <pthread.h>
#include "dns_resolver.h"
#include "./connectionTraffic.h"
#define MAXPENDING 32 // Maximum outstanding connection requests

#define MAX_ADDR_BUFFER 256
#define SELECTOR_CAPACITY 1024

static char addrBuffer[MAX_ADDR_BUFFER];

extern fd_handler CLIENT_HANDLER;

map hashmap = NULL; // Global hashmap to store user credentials
void client_handler_read(struct selector_key *key);
void client_handler_close(struct selector_key *key);



typedef enum CommandSocksv5 {
    CMD_CONNECT = 0x01,
    CMD_BIND = 0x02,
    CMD_UDP_ASSOCIATE = 0x03,
} CommandSocksv5;

typedef enum AddressTypeSocksv5 {
    SOCKSV5_ADDR_TYPE_IPV4 = 0x01,
    SOCKSV5_ADDR_TYPE_DOMAIN_NAME = 0x03,
    SOCKSV5_ADDR_TYPE_IPV6 = 0x04
} AddressTypeSocksv5;

typedef struct {
    char     host[256];
    char     service[6];
    fd_selector selector;
    void    *client_data;
} DnsJob;

static void *dns_thread_func(void *arg) {
    DnsJob *job = arg;
    int out_fd = dns_connect(job->host, job->service);
    if (out_fd >= 0) {
        ((ClientData*)job->client_data)->outgoing_fd = out_fd;
        selector_register(
            job->selector,
            out_fd,
            &CLIENT_HANDLER,        
            OP_WRITE,               // esperamos a que connect() termine, deberia ir algo del estilo OP_WRITE
            job->client_data
        );
    } else {
        // todo marcar error en client_data 
    }
    free(job);
    return NULL;
}

void stm_initial_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    memset(clientData->buffer, 0, sizeof(clientData->buffer));
}

StateSocksv5 stm_initial_read(struct selector_key *key) {
    ClientData *clientData = key->data; // TODO: validar si nos mandaron menos. ahora crashearia 

    ssize_t bytesRead = recv(key->fd, clientData->buffer, BUFSIZE, 0);
    if(bytesRead <= 0) {
        return STM_ERROR;
    }

    int index = 0;
    int version = clientData->buffer[index++];
    int methodCount = clientData->buffer[index++];

    char buffer[BUFSIZE] = {0};
    int string_index = 0;
    for(int i = 0; i < methodCount; i++) {
        string_index += sprintf(&buffer[string_index], "%d, ", clientData->buffer[index++]);
    }
    log(DEBUG, "version=%d methods[%d]=%s", version, methodCount, buffer);

    selector_set_interest_key(key, OP_WRITE); 

    return STM_INITIAL_WRITE;
}

StateSocksv5 stm_initial_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    
    ssize_t bytes = send(key->fd, "\x05\x02", 2, 0); // 0x02 = LOGIN
    selector_set_interest_key(key, OP_READ); 
    return STM_LOGIN_READ;

    // TODO: falta el caso de que el cliente haya seleccionado METHOD=NONE=0x00
    // return STM_REQUEST_READ;
}

void stm_login_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    memset(clientData->buffer, 0, BUFSIZE);
}

StateSocksv5 stm_login_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    char message[BUFSIZE] = {0};
    ssize_t bytes = recv(key->fd, clientData->buffer, BUFSIZE, 0);

    int index = 1;
    int usernameLen = clientData->buffer[index++];
    memcpy(message, &clientData->buffer[index], usernameLen);
    message[usernameLen] = '\0';
    index += usernameLen;
    int passwordLen = clientData->buffer[index++];
    memcpy(&message[usernameLen+1], &clientData->buffer[index], passwordLen);
    message[usernameLen + passwordLen + 1] = '\0';
    log(DEBUG, "username[%d]='%s' password[%d]='%s'", usernameLen, message, passwordLen, &message[usernameLen+1]);

    selector_set_interest_key(key, OP_WRITE); 
    return STM_LOGIN_WRITE;
}

StateSocksv5 stm_login_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    
    ssize_t bytes = send(key->fd, "\x05\x00", 2, 0);

    selector_set_interest_key(key, OP_READ); 
    return STM_REQUEST_READ;
}

void stm_request_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    memset(clientData->buffer, 0, BUFSIZE);
}

StateSocksv5 stm_request_read(struct selector_key *key) { // TODO: este de aca tiene MUCHA funcionalidad por hacer.
    ClientData *clientData = key->data;

    ssize_t bytes = recv(key->fd, clientData->buffer, BUFSIZE, 0);
    // TODO: Ojo que está ignorando la versión (debería rechazar si la versión es incorrecta)
    // Para rechazar deberíamos mandar un mensaje que diga "05 Connection Refused"
    int index = 1;
    CommandSocksv5 cmd = clientData->buffer[index++];
    switch (cmd) {
        case CMD_CONNECT:
            
            break;
        case CMD_BIND:
        case CMD_UDP_ASSOCIATE:
        default:
            log(ERROR, "client sent invalid COMMAND: 0x%x", cmd);
            // The reply specified REP as X'07' "Command not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
            send(key->fd, "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
            return STM_ERROR;
    }
    
    int reserved = clientData->buffer[index++]; // TODO: QUIZA CHEQUEAR QUE VALGA 0x00
    AddressTypeSocksv5 addressType = clientData->buffer[index++]; 
    uint32_t destinationIPv4;
    char hostname[MAX_ADDR_BUFFER + 1] = {0};
    int destinationPort = 0;

    struct addrinfo addrHints;
    memset(&addrHints, 0, sizeof(addrHints));
    addrHints.ai_socktype = SOCK_STREAM;
    addrHints.ai_protocol = IPPROTO_TCP;
    switch (addressType) {
        case SOCKSV5_ADDR_TYPE_IPV4: {
            addrHints.ai_family = AF_INET;
            struct in_addr addr;
            memcpy(&addr, &clientData->buffer[index], 4);
            // destinationIPv4 = htonl(*(uint32_t *)&clientData->buffer[index]);
            // printf("destAddress=%x ", destinationIPv4);
            index += 4;
            destinationPort = ntohs(*(uint16_t *)&clientData->buffer[index]);
            inet_ntop(AF_INET, &addr, hostname, INET_ADDRSTRLEN);
            break;
        }
        case SOCKSV5_ADDR_TYPE_DOMAIN_NAME:
            size_t domainNameSize = clientData->buffer[index++];
            char domainName[256] = {0};
            memcpy(domainName, &clientData->buffer[index], domainNameSize);
            memcpy(hostname, &clientData->buffer[index], domainNameSize);
            domainName[domainNameSize] = '\0';
            index += domainNameSize;

            destinationPort = ntohs(*(uint16_t *)&clientData->buffer[index]);
            index += 2;

            // printf("destAddress[%zu]='%s' port=%u\n", domainNameSize, domainName, destinationPort);
            // fflush(stdout);

            // char service_str[6];
            // snprintf(service_str, sizeof(service_str), "%u", port);

            // DnsJob *job = malloc(sizeof(*job));
            // strcpy(job->host, domainName);
            // strcpy(job->service, service_str);
            // job->selector    = key->s;
            // job->client_data = key->data;

            // pthread_t tid;
            // pthread_create(&tid, NULL, dns_thread_func, job);
            // pthread_detach(tid);

            // TODO(GAGO): llamar aca al thread de DNS. guardado en domainName con su domainNameSize
            // la respuesta se procesa en la funcion  stm_dns_done() que es el siguiente estado

            // return STM_DNS_DONE;
            break;
        case SOCKSV5_ADDR_TYPE_IPV6: {
            addrHints.ai_family = AF_INET6;
            struct in6_addr addr;
            memcpy(&addr, &clientData->buffer[index], 16);
            inet_ntop(AF_INET6, &addr, hostname, INET6_ADDRSTRLEN);
            index += 16;
            break;
        }
        default:
            log(ERROR, "client sent invalid ADDRESS_TYPE: 0x%x", cmd);
            // The reply specified REP as X'08' "Address type not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
            send(key->fd, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
            return STM_ERROR;
    }

    char service[6] = {0};
    sprintf(service, "%d", destinationPort);
    
    // uint16_t destinationPort = ntohs(*(uint16_t *)&clientData->buffer[index]);
    index += 2;
    int getAddrStatus = getaddrinfo(hostname, service, &addrHints, &clientData->connectAddresses);
    if(getAddrStatus != 0) {
        log(ERROR, "getaddrinfo() failed");
        // The reply specifies ATYP as IPv4 and BND as 0.0.0.0:0.
        char errorMessage[10] = "\x05 \x00\x01\x00\x00\x00\x00\x00\x00";
        // We calculate the REP value based on the type of error returned by getaddrinfo
        errorMessage[1] =
            getAddrStatus == EAI_FAMILY   ? '\x08'  // REP is "Address type not supported"
            : getAddrStatus == EAI_NONAME ? '\x04'  // REP is "Host Unreachable"
                                          : '\x01'; // REP is "General SOCKS server failure"
        send(key->fd, errorMessage, 10, 0);
        return STM_ERROR;
    }
    log(DEBUG, "cmd=%d addressType=%d destinationPort=%u", cmd, addressType, destinationPort);

    selector_set_interest_key(key, OP_WRITE); 
    return STM_REQUEST_WRITE;
}


StateSocksv5 stm_request_write(struct selector_key *key) {
    ClientData *clientData = key->data; 

    char message[BUFSIZE] = {0};
    int index = 0;
    message[index++] = SOCKS_PROTOCOL_VERSION;
    message[index++] = 0x00; // REPLY == 0x00 es que lo acepta
    message[index++] = 0x00; // RESERVED debe valer 0x00
    message[index++] = 0x01; // ADDRESS TYPE = 0x01 -> IPV4

    char addrBuf[64];
    int sock = -1;
    char addrBuffer[128];
    
    for (struct addrinfo* addr = clientData->connectAddresses; addr != NULL && sock == -1; addr = addr->ai_next) {
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock < 0) {
            log(ERROR, "Failed to create remote socket on %s", printAddressPort(addr, addrBuffer));
        } else {
            errno = 0;
            log(DEBUG, "Trying to connect() remote socket to %s: %s", printAddressPort(addr, addrBuffer), strerror(errno));
            if (connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
                log(ERROR, "Failed to connect() remote socket to %s: %s", printAddressPort(addr, addrBuffer), strerror(errno));
                close(sock);
                sock = -1;
            } else {
                log(DEBUG, "Successfully connected to: %s (%s %s) %s %s", printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuf));
            }
        }
    }
    
    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(sock, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        log(INFO, "Remote socket bound at %s", addrBuffer);
    } else {
        perror("[WRN] Failed to getsockname() for remote socket");
    }

    // Send a server reply: SUCCESS, then send the address to which our socket is bound.
    if (send(key->fd, "\x05\x00\x00", 3, 0) < 0)
        return -1;

    switch (boundAddress.ss_family) {
        case AF_INET:
            // Send: '\x01' (ATYP identifier for IPv4) followed by the IP and PORT.
            if (send(key->fd, "\x01", 1, 0) < 0)
                return -1;
            if (send(key->fd, &((struct sockaddr_in*)&boundAddress)->sin_addr, 4, 0) < 0)
                return -1;
            if (send(key->fd, &((struct sockaddr_in*)&boundAddress)->sin_port, 2, 0) < 0)
                return -1;
            break;

        case AF_INET6:
            // Send: '\x04' (ATYP identifier for IPv6) followed by the IP and PORT.
            if (send(key->fd, "\x04", 1, 0) < 0)
                return -1;
            if (send(key->fd, &((struct sockaddr_in6*)&boundAddress)->sin6_addr, 16, 0) < 0)
                return -1;
            if (send(key->fd, &((struct sockaddr_in6*)&boundAddress)->sin6_port, 2, 0) < 0)
                return -1;
            break;

        default:
            // We don't know the address type? Send IPv4 0.0.0.0:0.
            if (send(key->fd, "\x01\x00\x00\x00\x00\x00\x00", 7, 0) < 0)
                return -1;
            break;
    }
    clientData->outgoing_fd = sock;


    selector_set_interest_key(key, OP_READ);
    return STM_CONNECTION_TRAFFIC;
}

StateSocksv5 stm_dns_done(struct selector_key *key) {
    ClientData *clientData = key->data; 
    // TODO(GAGO): aca procesar el dns  
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(clientData->outgoing_fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
        log(ERROR, "connect() failed: %s", strerror(err));
        
        //todo chequear si esto esta bien como respuesta de ok
        char reply_err[10] = { 
            0x05,       // VERSION
            0x05,       // REP = connection refused
            0x00,       // RSV
            0x01, 0,0,0,0,  // ATYP=IPv4 + BND.ADDR = 0.0.0.0
            0,0         // BND.PORT = 0
        };
        send(clientData->client_fd, reply_err, sizeof(reply_err), 0);
        close(clientData->outgoing_fd);
        return STM_ERROR;
    }

    //todo chequear si esto esta bien como respuesta de ok
    char reply_ok[10] = {
        0x05,       
        0x00,       // REP = succeeded
        0x00,       
        0x01, 0,0,0,0, 
        0,0        
    };
    send(clientData->client_fd, reply_ok, sizeof(reply_ok), 0);

    selector_set_interest_key(key, OP_READ);
    selector_set_interest(key->s, clientData->client_fd, OP_READ);

    return STM_REQUEST_WRITE;
}

void stm_error(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data; 
    ssize_t bytes = recv(key->fd, clientData->buffer, BUFSIZE, 0);
    log(ERROR, "bytes recibidos: ");
    print_hex(clientData->buffer, bytes);
    selector_set_interest_key(key, OP_NOOP);
}

void stm_done_arrival(unsigned state, struct selector_key *key) {
    log(DEBUG, "done");
    selector_set_interest_key(key, OP_NOOP);
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
        .state = STM_CONNECTION_TRAFFIC, // se termino de establecer la conexion. y ahora se pasan los datos
        .on_arrival = stm_connection_traffic_arrival,
        .on_write_ready = stm_connection_traffic_write,
        .on_read_ready = stm_connection_traffic_read,
        .on_departure = stm_connection_traffic_departure,
    },
    {
        .state = STM_DNS_DONE, 
        .on_block_ready = stm_dns_done,
    },
    ///
    {
        .state = STM_DONE, 
        .on_arrival = stm_done_arrival, 
    },
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
        // man 7 ip. no importa reportar nada si falla.
        setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
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
	struct sockaddr_storage clntAddr;
	socklen_t clntAddrLen = sizeof(clntAddr);

	// Wait for a client to connect
	int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
	if (clntSock < 0) {
		log(ERROR, "accept() failed");
		return -1;
	}
    if(selector_fd_set_nio(clntSock < 0)) {
        log(ERROR, "accept() failed");
        return -1;
    }

	printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);
	log(INFO, "Handling client %s", addrBuffer);

	return clntSock;
}

void client_handler_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    StateSocksv5 state = stm_handler_read(&clientData->stm, key);
    if(state == STM_ERROR) {
        client_handler_close(key);
    }
}

void client_handler_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    StateSocksv5 state = stm_handler_write(&clientData->stm, key);
    if(state == STM_ERROR) {
        client_handler_close(key);
    }
}
void client_handler_block(struct selector_key *key) {
    ClientData *clientData = key->data;
    StateSocksv5 state = stm_handler_block(&clientData->stm, key);
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
    log(INFO, "handling client close");
    free(key->data);
}

fd_handler CLIENT_HANDLER = {
    .handle_read = client_handler_read,
    .handle_write = client_handler_write,
    .handle_block = client_handler_block,
    .handle_close = client_handler_close,
};
void handle_read_passive(struct selector_key *key) {
    int clientSocket = acceptTCPConnection(key->fd);

    ClientData *clientData = calloc(1, sizeof(ClientData)); 
    
    clientData->stm.initial = STM_INITIAL_READ;
    clientData->stm.max_state = STM_ERROR;
    clientData->stm.states = CLIENT_STATE_TABLE;
    clientData->client_fd   = clientSocket;
    clientData->outgoing_fd = -1;
    stm_init(&clientData->stm);

    selector_register(key->s, clientSocket, &CLIENT_HANDLER, OP_READ, (void *)clientData);
}

static void
sigterm_handler(const int signal) {
    log(INFO, "signal %d, cleaning up and exiting", signal);
    exit(1);
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    close(STDIN_FILENO);

    hashmap = map_create();
    map_set(hashmap, "john", "doe");
    map_set(hashmap, "alex", "1234");
    if(map_contains(hashmap, "john") == true) {
        log(INFO, "User john is in the map");
    }
    log(INFO, "Map created with %d elements", map_size(hashmap));

    if (argc > 2) {
        log(FATAL, "usage: %s <Server Port>", argv[0]);
    }

    int servSock = setupTCPServerSocket((argc == 1) ? "1024" : argv[1]);
    if (servSock < 0) return 1;

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    if (selector_fd_set_nio(servSock) < 0) {
        log(FATAL, "Could not set O_NONBLOCK on listening socket");
    }

    const struct selector_init conf = {
        .signal = SIGALRM,          
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 }
    };
    selector_init(&conf);
    fd_selector selector = selector_new(SELECTOR_CAPACITY);

    static const fd_handler listen_handler = {
        .handle_read  = handle_read_passive,
        .handle_write = NULL,
        .handle_block = NULL,
        .handle_close = NULL
    };
    selector_register(selector, servSock, &listen_handler, OP_READ, NULL);

    while (selector_select(selector) == SELECTOR_SUCCESS) {
        ; 
    }

    selector_destroy(selector);
	selector_close();
    if(servSock >= 0) {
        close(servSock);
    }
    return 0;
}
