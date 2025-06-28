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

#define BUFSIZE 1024
#define MAX_ADDR_BUFFER 256
#define MAX_STR_BUFFER 256

typedef struct ClientData {
    int           client_fd;    // descriptor del socket del cliente SOCKS
    int           outgoing_fd; 
    struct addrinfo *connectAddresses;
    char buffer[BUFSIZE];
    char clientBufferData[BUFSIZE];
    char remoteBufferData[BUFSIZE];
    ssize_t bytes;
    struct state_machine stm;
    buffer client_buffer;  // buffer para almacenar datos del socket del cliente
    buffer outgoing_buffer; // buffer para almacenar datos del socket remoto

    size_t to_read; // Cantidad de bytes que faltan por leer del cliente

    // LOGIN
    uint8_t user_length; // Longitud del nombre de usuario
    uint8_t pass_length; // Longitud de la contraseña
    char username[MAX_STR_BUFFER]; // Nombre de usuario del cliente
    char password[MAX_STR_BUFFER]; // Contraseña del cliente

    // REQUEST
    uint8_t cmd;
    uint8_t addressType;
    char unresolved_hostname[MAX_ADDR_BUFFER + 1];
    uint16_t destinationPort;
    struct addrinfo addrHints;
    struct in_addr ipv4_addr; // Dirección IPv4 del destino
    struct in6_addr ipv6_addr; // Dirección IPv6 del destino


} ClientData;

typedef enum StateSocksv5 {
    STM_INITIAL_READ_VERSION = 0,
    STM_INITIAL_READ_METHOD_COUNT,
    STM_INITIAL_READ_METHODS,

    STM_INITIAL_WRITE,

    STM_LOGIN_READ_VERSION,
    STM_LOGIN_READ_USER_COUNT,
    STM_LOGIN_READ_USER,
    STM_LOGIN_READ_PASS_COUNT,
    STM_LOGIN_READ_PASS,

    STM_LOGIN_WRITE,

    STM_REQUEST_READ_VERSION,
    STM_REQUEST_READ_CMD,
    STM_REQUEST_READ_RESERVED,
    STM_REQUEST_READ_ATYP,
    STM_REQUEST_READ_IPV4,
    STM_REQUEST_READ_DOMAIN_NAME_SIZE,
    STM_REQUEST_READ_DOMAIN_NAME,
    STM_REQUEST_READ_IPV6,
    STM_REQUEST_READ_PORT,

    STM_REQUEST_WRITE,

    STM_REQUEST_CONNECT,

    STM_CONNECTION_TRAFFIC,

    STM_DNS_DONE,

    STM_DONE,

    STM_ERROR, // DEBE SER EL ULTIMO

} StateSocksv5;

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


// todo pasar este struct y esta funcion al dns_resolver de alguna manera
typedef struct {
    char host[256];
    char service[6];
    struct addrinfo **result;  // aquí guardamos la lista devuelta
    fd_selector     selector;
    int             client_fd;
} DnsJob;


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
