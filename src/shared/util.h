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

#define BUFSIZE (32768) /* 32 KB */
#define MAX_ADDR_BUFFER (64)
#define NAME_MAX_LENGTH (256) /* si no ponemos 256, entonces stackbufferoverflow */
#define SOCKS_LOGIN_VERSION (1)


typedef enum AuthMethod {
    AUTH_NONE = 0x00,
    AUTH_GSSAPI = 0x01,
    AUTH_USER_PASSWORD = 0x02,
    AUTH_NO_ACCEPTABLE = 0xFF
} AuthMethod;

typedef struct socks5_initial_parserinfo {
    // -------- Datos parseados --------
    uint8_t socksVersion; 
    uint8_t methodCount; 
    uint8_t authMethods[256];
    // -------- Datos internos del parser --------
    uint8_t substate;
} socks5_initial_parserinfo;

typedef struct socks5_login_parserinfo {
    // -------- Datos parseados --------
    uint8_t loginVersion;
    uint8_t usernameLength;
    char username[NAME_MAX_LENGTH];
    uint8_t passwordLength;
    char password[NAME_MAX_LENGTH];
    // -------- Datos internos del parser --------
    uint8_t substate;
} socks5_login_parserinfo;

typedef struct socks5_request_parserinfo {
    // -------- Datos parseados --------
    uint8_t socksVersion; // Debe ser 5
    uint8_t command; // CMD_CONNECT, CMD_BIND, CMD_UDP_ASSOCIATE
    uint8_t reserved; // Ignorar
    uint8_t addressType; // SOCKSV5_ADDR_TYPE_IPV4, SOCKSV5_ADDR_TYPE_DOMAIN_NAME, SOCKSV5_ADDR_TYPE_IPV6
    uint8_t dummy_bytes[4];
    struct in_addr ipv4;
    struct in6_addr ipv6;
    uint8_t domainNameLength; // Longitud del nombre de dominio
    char domainName[NAME_MAX_LENGTH];
    uint16_t port; // Puerto del destino
    union {
        struct sockaddr_in sockAddress; 
        struct sockaddr_in6 sockAddress6; 
    };
    // -------- Datos internos del parser --------
    uint8_t substate;
} socks5_request_parserinfo;

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
    uint8_t username[NAME_MAX_LENGTH];
    char isLoggedIn;
    AuthMethod authMethod;

    int client_closed; // Indica si el cliente ha cerrado la conexión
    int outgoing_closed; // Indica si el socket remoto ha cerrado la conexión
    int server_is_connecting;
    union {
        socks5_initial_parserinfo initialParserInfo;
        socks5_login_parserinfo loginParserInfo;
        socks5_request_parserinfo requestParser;
    };

    ssize_t toWrite;
    ssize_t toRead;
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
    STM_ERROR_MSG_WRITE,
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
