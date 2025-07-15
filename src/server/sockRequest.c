#include "./sockRequest.h"
#include "../shared/util.h"
#include "../monitoring/monitoringMetrics.h"
#include "sockUtils.h"
#include "socks5.h"
#include "initialParser.h"
#include "connectionTraffic.h"

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

typedef enum RequestStatus {
    REQUEST_SUCCEED = 0x00,
    REQUEST_GENERAL_FAILURE = 0x01,
    REQUEST_CONNECTION_NOT_ALLOWED = 0x02,
    REQUEST_NETWORK_UNREACHABLE = 0x03,
    REQUEST_HOST_UNREACHABLE = 0x04,
    REQUEST_CONNECTION_REFUSED = 0x05,
    REQUEST_TTL_EXPIRED = 0x06,
    REQUEST_COMMAND_NOT_SUPPORTED = 0x08,
} RequestStatus;


StateSocksv5 beginConnection(struct selector_key *key);

static RequestStatus errnoToRequestStatus(int err) {
    switch (err)
    {
    case 0:
        return REQUEST_SUCCEED;
    case ENETUNREACH:
        return REQUEST_NETWORK_UNREACHABLE;
    case EHOSTUNREACH:
        return REQUEST_HOST_UNREACHABLE;
    case ECONNREFUSED:
        return REQUEST_CONNECTION_REFUSED;
    case ETIMEDOUT:
        return REQUEST_TTL_EXPIRED;
    default:
        return REQUEST_GENERAL_FAILURE;
    }
}

void stm_request_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    request_initialize(&clientData->requestParser, &clientData->toRead);
    buffer_reset(&clientData->client_buffer);
}

StateSocksv5 stm_request_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    socks5_request_parserinfo *parserInfo = &clientData->requestParser;
    // 1. Guardo datos en el buffer (sin que se lean bytes de más)
    ssize_t bytesRead = recv_ToBuffer_WithMetrics(key->fd, &clientData->client_buffer, clientData->toRead);

    // 1,5. Manejo de errores [READ]
    if(bytesRead <= 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            errno = 0;
            return STM_REQUEST_READ; // No se pudo leer, pero no hubo error
        }
        if (bytesRead == 0) {
            log(DEBUG, "Connection closed by peer [CLIENT] on socket %d", key->fd);
            selector_set_interest_key(key, OP_NOOP);
            return STM_DONE; // No se cierra el socket, solo se marca como cerrado
        }
        log(DEBUG, "Failed to read request data from client fd=%d: %s", key->fd, strerror(errno));
        errno = 0;
        return STM_DONE;
    }

    // 2. Parsing (de lo que hay en el buffer)
    clientData->toRead -= bytesRead;
    switch(request_parse(&clientData->client_buffer, parserInfo, &clientData->toRead)) {
        case PARSER_OK:
            break; // Termino el parsing
        case PARSER_INCOMPLETE:
            return STM_REQUEST_READ; // No se recibieron tod0s los bytes necesarios
        case PARSER_ERROR:
            // log(ERROR, "Error parsing request data");
            return prepare_error(key, "\x05\x01\x00\x01\x00\x00\x00\x00\x00", 10);
    }

    // 3. Acciones
    log(DEBUG, "Parsed request: command=%d, addressType=%d, port=%d, domainNameLength=%d",
        parserInfo->command, parserInfo->addressType, parserInfo->port, parserInfo->domainNameLength);
    CommandSocksv5 cmd = parserInfo->command;
    switch (cmd) {
        case CMD_CONNECT:
            break;
        case CMD_BIND:
        case CMD_UDP_ASSOCIATE:
            log(DEBUG, "Command not implemented: 0x%x", parserInfo->command);
        default:
            log(DEBUG, "client sent invalid COMMAND: 0x%x", parserInfo->command);
            // The reply specified REP as X'07' "Command not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
            return prepare_error(key, "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10);
    }

    AddressTypeSocksv5 addressType = parserInfo->addressType;

    switch (addressType) {
        case SOCKSV5_ADDR_TYPE_IPV4: {
            clientData->connectAddresses = calloc(1, sizeof(struct addrinfo)); // este se libera en freeaddrinfo()
            if (clientData->connectAddresses == NULL) {
                log(DEBUG, "couldnt allocate memory for addr info: fd=%d", key->fd);
                break;
            }
            parserInfo->sockAddress = (struct sockaddr_in) {
                .sin_family = AF_INET,
                .sin_addr = parserInfo->ipv4,
                .sin_port = htons(parserInfo->port),
            };
            
            *clientData->connectAddresses = (struct addrinfo) {
                .ai_family = AF_INET,
                .ai_addr = (struct sockaddr*) &parserInfo->sockAddress,
                .ai_addrlen = sizeof(struct sockaddr_in),
                .ai_socktype = SOCK_STREAM,
                .ai_protocol = IPPROTO_TCP,
            };
            
            return beginConnection(key);
        }
        case SOCKSV5_ADDR_TYPE_DOMAIN_NAME: {
            DnsJob *job = calloc(1, sizeof(*job)); // este se libera en dns_thread_func
            if (!job) {
                log(DEBUG, "malloc: %s", strerror(errno));
                break;
            }
            uint8_t domainNameSize = parserInfo->domainNameLength;
            memcpy(job->host, parserInfo->domainName, domainNameSize);
            job->host[domainNameSize] = '\0'; // Null-terminate the domain

            pthread_t tid;
            snprintf(job->service, sizeof(job->service), "%u", parserInfo->port);

            job->result = &clientData->connectAddresses;
            job->client_fd = clientData->client_fd;
            job->selector = key->s;

            if (pthread_create(&tid, NULL, dns_thread_func, job) != 0) {
                log(ERROR, "pthread_create: %s", strerror(errno));
                free(job);
                break;
            }
            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
                break;
            }
            pthread_detach(tid);

            return STM_DNS_DONE;
        }
        case SOCKSV5_ADDR_TYPE_IPV6: {
            clientData->connectAddresses = calloc(1, sizeof(struct addrinfo)); // este se libera en freeaddrinfo()
            if (clientData->connectAddresses == NULL) {
                log(ERROR, "couldnt allocate memory for addr info: fd=%d", key->fd);
                break;
            }
            parserInfo->sockAddress6 = (struct sockaddr_in6) {
                .sin6_family = AF_INET6,
                .sin6_addr = parserInfo->ipv6,
                .sin6_port = htons(parserInfo->port),
            };

            *clientData->connectAddresses = (struct addrinfo) {
                .ai_family = AF_INET6,
                .ai_addr = (struct sockaddr*) &parserInfo->sockAddress6,
                .ai_addrlen = sizeof(struct sockaddr_in6),
            };

            return beginConnection(key);
        }
        default:
            log(DEBUG, "client sent invalid ADDRESS_TYPE: 0x%x", addressType);
            // The reply specified REP as X'08' "Address type not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
            return prepare_error(key, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10);
    }
    // The reply specified REP as X'01' "General error", ATYP as IPv4 and BND as 0.0.0.0:0.
    return prepare_error(key, "\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00", 10);
}

fd_handler PROXY_HANDLER = {
    .handle_read = proxy_handler_read,
    .handle_write = proxy_handler_write,
    .handle_block = proxy_handler_block,
    .handle_close = proxy_handler_close,
};

StateSocksv5 beginConnection(struct selector_key *key) {
    ClientData *clientData = key->data;
    selector_set_interest(key->s, clientData->client_fd, OP_WRITE);
    char addrBuffer[MAX_ADDR_BUFFER] = {0};
    struct addrinfo* addr = clientData->connectAddresses;
    while (addr != NULL && clientData->outgoing_fd == -1) {
        clientData->outgoing_fd = socket(addr->ai_family, SOCK_NONBLOCK | SOCK_STREAM, addr->ai_protocol);
        if (clientData->outgoing_fd < 0) {
            clientData->outgoing_fd = socket(addr->ai_family, SOCK_STREAM, addr->ai_protocol);
        }
        if (clientData->outgoing_fd < 0) {
            log(DEBUG, "Failed to create remote socket on %s", printAddressPort(addr, addrBuffer));

            clientData->connectAddresses = NULL;
            return prepare_error(key, "\x05\x01\x00\x01\x00\x00\x00\x00\x00", 10);
        }
        selector_fd_set_nio(clientData->outgoing_fd);
        errno = 0;
        if (connect(clientData->outgoing_fd, addr->ai_addr, addr->ai_addrlen) == 0 || errno == EINPROGRESS) {
            clientData->server_is_connecting = 1;
            selector_register(key->s, clientData->outgoing_fd, &PROXY_HANDLER, OP_WRITE, key->data);
            selector_set_interest(key->s, clientData->client_fd, OP_NOOP);
            return STM_CONNECT_ATTEMPT;
        } else {
            log(DEBUG, "Failed to connect() remote socket to %s: %s", printAddressPort(addr, addrBuffer), strerror(errno));
            close(clientData->outgoing_fd);
            clientData->outgoing_fd = -1;
            addr = addr->ai_next;
        }
    }

    return prepare_error(key, "\x05\x01\x00\x00\x00\x00\x00\x00\x00", 10);
}

StateSocksv5 stm_request_write(struct selector_key *key) {
    return write_everything(key, STM_REQUEST_WRITE, OP_READ, STM_CONNECTION_TRAFFIC);
}

StateSocksv5 stm_dns_done(struct selector_key *key) {
    ClientData *clientData = key->data; 
    selector_set_interest(key->s, clientData->client_fd, OP_WRITE);
    if(clientData->connectAddresses == NULL) {
        return prepare_error(key, "\x05\x04\x00\x00\x00\x00\x00\x00\x00", 10);
    }
    return beginConnection(key);
}

void stm_connect_attempt_arrival(unsigned state, struct selector_key *key) {

}

StateSocksv5 stm_connect_attempt_write(struct selector_key *key) {
    ClientData *clientData = key->data; 

    clientData->server_is_connecting = 0;
    selector_set_interest(key->s, clientData->outgoing_fd, OP_NOOP);

    char addrBuffer[MAX_ADDR_BUFFER] = {0};
    int sock = clientData->outgoing_fd;
    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(sock, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        log(DEBUG, "Remote socket bound at %s", addrBuffer);
    } else {
        selector_unregister_fd(key->s, clientData->outgoing_fd);
        return prepare_error(key, "\x05\x01\x00\x01\x00\x00\x00\x00\x00", 10);
    }
    int err = 0;
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &(socklen_t){sizeof(int)})) {
        log(DEBUG, "connect attempt error %d", key->fd);
        selector_unregister_fd(key->s, clientData->outgoing_fd);
        return prepare_error(key, "\x05\x01\x00\x01\x00\x00\x00\x00\x00", 10);
    }

    if(err) {
        log(DEBUG, "connect attempt error %d err=%d", key->fd, err);
        char errorRes[] = "\x05\x01\x00\x01\x00\x00\x00\x00\x00";
        errorRes[1] = errnoToRequestStatus(err);
        selector_unregister_fd(key->s, clientData->outgoing_fd);
        return prepare_error(key, errorRes, 10);
    }
    
    // sendBytesWithMetrics a server reply: SUCCESS, then sendBytesWithMetrics the address to which our socket is bound.

    buffer_reset(&clientData->outgoing_buffer);
    size_t bufferLimit = 0;
    uint8_t *writePtr = buffer_write_ptr(&clientData->outgoing_buffer, &bufferLimit);

    memcpy(writePtr, "\x05\x00\x00", 3); // Version, REP, RSV

    switch (boundAddress.ss_family) {
        case AF_INET:
            writePtr[3] = '\x01'; // ATYP identifier for IPv4
            memcpy(writePtr + 3 + 1, &((struct sockaddr_in*)&boundAddress)->sin_addr, sizeof(struct in_addr));
            memcpy(writePtr + 3 + 1 + sizeof(struct in_addr), &((struct sockaddr_in*)&boundAddress)->sin_port, sizeof(uint16_t));
            buffer_write_adv(&clientData->outgoing_buffer, 3 + sizeof(struct in_addr) + 1 + sizeof(uint16_t));
            clientData->toWrite = 3 + sizeof(struct in_addr) + 1 + sizeof(uint16_t);
            break;

        case AF_INET6:
            writePtr[3] = '\x04'; // ATYP identifier for IPv6
            memcpy(writePtr + 3 + 1, &((struct sockaddr_in6*)&boundAddress)->sin6_addr, sizeof(struct in6_addr));
            memcpy(writePtr + 3 + 1 + sizeof(struct in6_addr), &((struct sockaddr_in6*)&boundAddress)->sin6_port, sizeof(uint16_t));
            buffer_write_adv(&clientData->outgoing_buffer, 3 + sizeof(struct in6_addr) + 1 + sizeof(uint16_t));
            clientData->toWrite = 3 + sizeof(struct in6_addr) + 1 + sizeof(uint16_t);
            break;

        default:
            // We don't know the address type? sendBytesWithMetrics IPv4 0.0.0.0:0.
            selector_unregister_fd(key->s, clientData->outgoing_fd);
            return prepare_error(key, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10);
    }
    clientData->outgoing_fd = sock;
    struct addrinfo *addr = clientData->connectAddresses; 
    if(clientData->isLoggedIn) {
        log(INFO, "[%d] User %s Successfully connected to: %s (%s %s) %s %s", key->fd, clientData->username, printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuffer));
    }
    else {
        log(INFO, "[%d] NO-AUTH Successfully connected to: %s (%s %s) %s %s", key->fd, printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuffer));
    }

    selector_set_interest_key(key, OP_WRITE);
    return STM_REQUEST_WRITE;
}