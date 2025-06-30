#ifndef UTIL_SOCKS5_H_
#define UTIL_SOCKS5_H_

#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "../shared/logger.h"
#include "../selector.h"
#include "../parser.h"
#include <signal.h>
#include "../stm.h"
#include <pthread.h>
#include "../buffer.h"

#define BUFSIZE (4096)
#define MAX_ADDR_BUFFER (64)
#define USERNAME_MAX_LENGTH (256)
#define SOCKS_LOGIN_VERSION (1)

typedef enum AuthMethod {
    AUTH_NONE = 0x00,
    AUTH_GSSAPI = 0x01,
    AUTH_USER_PASSWORD = 0x02,
    AUTH_NO_ACCEPTABLE = 0xFF
} AuthMethod;

typedef struct ClientData {
    int           client_fd;    // descriptor del socket del cliente SOCKS
    int           outgoing_fd; 
    struct addrinfo *connectAddresses;
    ssize_t bytes;
    struct state_machine stm;
    buffer client_buffer;  // buffer para almacenar datos del socket del cliente
    uint8_t clientBufferData[BUFSIZE];
    buffer outgoing_buffer; // buffer para almacenar datos del socket remoto
    uint8_t remoteBufferData[BUFSIZE];
    char username[USERNAME_MAX_LENGTH];
    // parsing
    AuthMethod authMethod;
    //
} ClientData;

typedef enum StateSocksv5 {
    STM_INITIAL_READ = 0,
    STM_INITIAL_WRITE,
    STM_LOGIN_READ,
    STM_LOGIN_WRITE,
    STM_REQUEST_READ,
    STM_REQUEST_WRITE,
    STM_CONNECT_ATTEMPT,
    STM_CONNECTION_TRAFFIC,
    STM_DNS_DONE,
    STM_DONE,
    STM_ERROR, // ERROR DEBE SER EL ULTIMO
} StateSocksv5;


#define ERROR_VALUE (-1)
#define SOCKS_PROTOCOL_VERSION (5)

int printSocketAddress(const struct sockaddr *address, char * addrBuffer);

const char * printFamily(struct addrinfo *aip);
const char * printType(struct addrinfo *aip);
const char * printProtocol(struct addrinfo *aip);
void printFlags(struct addrinfo *aip);
char * printAddressPort( const struct addrinfo *aip, char addr[]);

// Determina si dos sockets son iguales (misma direccion y puerto)
int sockAddrsEqual(const struct sockaddr *addr1, const struct sockaddr *addr2);

#endif 
