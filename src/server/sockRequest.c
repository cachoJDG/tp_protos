#include "./sockRequest.h"
#include "../shared/util.h"
#include "../monitoring/monitoringMetrics.h"
#include "sockUtils.h"
#include "socks5.h"
#include "initialParser.h"

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
    char host[MAX_ADDR_BUFFER];
    char service[8];
    struct addrinfo **result;  // aquí guardamos la lista devuelta
    fd_selector     selector;
    int             client_fd;
} DnsJob;

StateSocksv5 beginConnection(struct selector_key *key);

void *dns_thread_func(void *arg) {
    DnsJob *job = (DnsJob *)arg;
    if (dns_solve_addr(job->host, job->service, job->result) == 0) {
        struct addrinfo *p;
        char ipstr[INET6_ADDRSTRLEN];

        for (p = *job->result; p != NULL; p = p->ai_next) {
            void *addr;
            if (p->ai_family == AF_INET) {
                addr = &((struct sockaddr_in *)p->ai_addr)->sin_addr;
            } else {  // AF_INET6
                addr = &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr;
            }
            inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
            // log(DEBUG, "DNS resuelto para %s:%s -> %s", job->host, job->service, ipstr);
        }

    } else {
        // log(ERROR, "Error al resolver DNS para %s:%s", job->host, job->service);
        job->result = NULL;
    }
    selector_notify_block(job->selector, job->client_fd);
    free(job);
    return NULL;
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

    if (bytesRead <= 0) {
        log(ERROR, "stm machine inconsistency: read handler called without bytes to read %ld", bytesRead);
        sendBytesWithMetrics(key->fd, "\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return STM_ERROR;
    }

    // 2. Parsing (de lo que hay en el buffer)
    clientData->toRead -= bytesRead;
    switch(request_parse(&clientData->client_buffer, parserInfo, &clientData->toRead)) {
        case PARSER_OK:

            break; // Termino el parsing
        case PARSER_INCOMPLETE:
            return STM_REQUEST_READ; // No se recibieron todos los bytes necesarios
        case PARSER_ERROR:
            // log(ERROR, "Error parsing request data");
            sendBytesWithMetrics(key->fd, "\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
            return STM_ERROR;
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
            log(ERROR, "Command not implemented: 0x%x", parserInfo->command);
        default:
            log(ERROR, "client sent invalid COMMAND: 0x%x", parserInfo->command);
            // The reply specified REP as X'07' "Command not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
            sendBytesWithMetrics(key->fd, "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
            return STM_ERROR;
    }

    AddressTypeSocksv5 addressType = parserInfo->addressType;

    switch (addressType) {
        case SOCKSV5_ADDR_TYPE_IPV4: {
            clientData->connectAddresses = calloc(1, sizeof(struct addrinfo)); // este se libera en freeaddrinfo()
            if (clientData->connectAddresses == NULL) {
                log(ERROR, "couldnt allocate memory for addr info: fd=%d", key->fd);
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
                log(ERROR, "malloc: %s", strerror(errno));
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
            log(ERROR, "client sent invalid ADDRESS_TYPE: 0x%x", addressType);
            // The reply specified REP as X'08' "Address type not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
            sendBytesWithMetrics(key->fd, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
            return STM_ERROR;
    }
    // The reply specified REP as X'01' "General error", ATYP as IPv4 and BND as 0.0.0.0:0.
    sendBytesWithMetrics(key->fd, "\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
    return STM_ERROR;
}

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
            log(ERROR, "Failed to create remote socket on %s", printAddressPort(addr, addrBuffer));
            sendBytesWithMetrics(key->fd, "\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
            return STM_ERROR;
        }
        selector_fd_set_nio(clientData->outgoing_fd);
        errno = 0;
        if (connect(clientData->outgoing_fd, addr->ai_addr, addr->ai_addrlen) == 0 || errno == EINPROGRESS) {
            log(DEBUG, "Successfully connected to: %s (%s %s) %s %s", printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuffer));
            metrics_increment_connections();
            return STM_CONNECT_ATTEMPT;
        } else {
            log(ERROR, "Failed to connect() remote socket to %s: %s", printAddressPort(addr, addrBuffer), strerror(errno));
            close(clientData->outgoing_fd);
            clientData->outgoing_fd = -1;
            struct addrinfo* next_addr = addr->ai_next;
            freeaddrinfo(addr);
            addr = next_addr;
        }
    }

    sendBytesWithMetrics(key->fd, "\x05\x04\x00\x00\x00\x00\x00\x00\x00", 10, 0);
    return STM_ERROR;
}

StateSocksv5 stm_request_write(struct selector_key *key) {
    // ClientData *clientData = key->data; 
  
    return STM_ERROR;
}

StateSocksv5 stm_dns_done(struct selector_key *key) {
    ClientData *clientData = key->data; 
    selector_set_interest(key->s, clientData->client_fd, OP_WRITE);
    if(clientData->connectAddresses == NULL) {
        sendBytesWithMetrics(key->fd, "\x05\x04\x00\x00\x00\x00\x00\x00\x00", 10, 0);
        return STM_ERROR;
    }
    return beginConnection(key);
}

void stm_connect_attempt_arrival(unsigned state, struct selector_key *key) {

}

StateSocksv5 stm_connect_attempt_write(struct selector_key *key) {
    ClientData *clientData = key->data; 
    char addrBuffer[MAX_ADDR_BUFFER];
    int sock = clientData->outgoing_fd;
    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(sock, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        log(INFO, "Remote socket bound at %s", addrBuffer);
    } else {
        sendBytesWithMetrics(key->fd, "\x05\x04\x00\x04\x00\x00\x00\x00\x00", 10, 0);
        return STM_ERROR;
    }
    
    // sendBytesWithMetrics a server reply: SUCCESS, then sendBytesWithMetrics the address to which our socket is bound.
    if (sendBytesWithMetrics(key->fd, "\x05\x00\x00", 3, 0) <= 0) {
        log(ERROR, "connecting to remote: send failed %d", key->fd);
        sendBytesWithMetrics(key->fd, "\x05\x04\x00\x01\x00\x00\x00\x00\x00", 10, 0);
        return STM_ERROR;
    }

    switch (boundAddress.ss_family) {
        case AF_INET:
            // sendBytesWithMetrics: '\x01' (ATYP identifier for IPv4) followed by the IP and PORT.
            if (sendBytesWithMetrics(key->fd, "\x01", 1, 0) <= 0) {
                sendBytesWithMetrics(key->fd, "\x05\x04\x00\x01\x00\x00\x00\x00\x00", 10, 0);
                return STM_ERROR;
            }
            if (sendBytesWithMetrics(key->fd, &((struct sockaddr_in*)&boundAddress)->sin_addr, 4, 0) <= 0) {
                sendBytesWithMetrics(key->fd, "\x05\x04\x00\x01\x00\x00\x00\x00\x00", 10, 0);
                return STM_ERROR;
            }
            if (sendBytesWithMetrics(key->fd, &((struct sockaddr_in*)&boundAddress)->sin_port, 2, 0) <= 0) {
                sendBytesWithMetrics(key->fd, "\x05\x04\x00\x01\x00\x00\x00\x00\x00", 10, 0);
                return STM_ERROR;
            }
            break;

        case AF_INET6:
            // sendBytesWithMetrics: '\x04' (ATYP identifier for IPv6) followed by the IP and PORT.
            if (sendBytesWithMetrics(key->fd, "\x04", 1, 0) <= 0) {
                sendBytesWithMetrics(key->fd, "\x05\x04\x00\x01\x00\x00\x00\x00\x00", 10, 0);
                return STM_ERROR;
            }
            if (sendBytesWithMetrics(key->fd, &((struct sockaddr_in6*)&boundAddress)->sin6_addr, 16, 0) <= 0) {
                sendBytesWithMetrics(key->fd, "\x05\x04\x00\x01\x00\x00\x00\x00\x00", 10, 0);
                return STM_ERROR;
            }
            if (sendBytesWithMetrics(key->fd, &((struct sockaddr_in6*)&boundAddress)->sin6_port, 2, 0) <= 0) {
                sendBytesWithMetrics(key->fd, "\x05\x04\x00\x01\x00\x00\x00\x00\x00", 10, 0);
                return STM_ERROR;
            }
            break;

        default:
            // We don't know the address type? sendBytesWithMetrics IPv4 0.0.0.0:0.
            if (sendBytesWithMetrics(key->fd, "\x01\x00\x00\x01\x00\x00\x00", 7, 0) <= 0) {
                return STM_ERROR;
            }
            break;
    }
    clientData->outgoing_fd = sock;
    freeaddrinfo(clientData->connectAddresses);

    selector_set_interest_key(key, OP_READ);
    return STM_CONNECTION_TRAFFIC;
}