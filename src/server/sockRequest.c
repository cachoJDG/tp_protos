#include "./sockRequest.h"

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
    char service[6];
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
            log(DEBUG, "DNS resuelto para %s:%s -> %s", job->host, job->service, ipstr);
        }

    } else {
        log(ERROR, "Error al resolver DNS para %s:%s", job->host, job->service);
        job->result = NULL;
    }
    free(job);
    selector_notify_block(job->selector, job->client_fd);
    return NULL;
}

void stm_request_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    memset(clientData->buffer, 0, BUFSIZE);
}

StateSocksv5 stm_request_read(struct selector_key *key) {
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
    char hostname[MAX_ADDR_BUFFER] = {0};
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
        case SOCKSV5_ADDR_TYPE_DOMAIN_NAME: {
            DnsJob *job = calloc(1, sizeof(*job));
            if (!job) {
                log(ERROR, "malloc: %s", strerror(errno));
                return STM_ERROR;
            }
            size_t domainNameSize = clientData->buffer[index++];
            strncpy(job->host, &clientData->buffer[index], sizeof(job->host) - 1);
            index += domainNameSize;

            destinationPort = ntohs(*(uint16_t *)&clientData->buffer[index]);
            index += 2;

            pthread_t tid;
            snprintf(job->service, sizeof(job->service) - 1, "%u", destinationPort);

            job->result = &clientData->connectAddresses;
            job->client_fd = clientData->client_fd;
            job->selector = key->s;

            if (pthread_create(&tid, NULL, dns_thread_func, job) != 0) {
                log(ERROR, "pthread_create: %s", strerror(errno));
                free(job);
                return STM_ERROR;
            }
            pthread_detach(tid);

            return STM_DNS_DONE;
        }
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
        char errorMessage[] = "\x05\x00\x01\x00\x00\x00\x00\x00\x00";
        // We calculate the REP value based on the type of error returned by getaddrinfo
        errorMessage[1] =
            getAddrStatus == EAI_FAMILY   ? '\x08'  // REP is "Address type not supported"
            : getAddrStatus == EAI_NONAME ? '\x04'  // REP is "Host Unreachable"
                                          : '\x01'; // REP is "General SOCKS server failure"
        send(key->fd, errorMessage, sizeof(errorMessage), 0);
        return STM_ERROR;
    }
    log(DEBUG, "cmd=%d addressType=%d destinationPort=%u", cmd, addressType, destinationPort);

    selector_set_interest_key(key, OP_WRITE); 

    return beginConnection(key);
}

StateSocksv5 beginConnection(struct selector_key *key) {
    ClientData *clientData = key->data;
    char addrBuffer[MAX_ADDR_BUFFER] = {0};
    
    for (struct addrinfo* addr = clientData->connectAddresses; addr != NULL && clientData->outgoing_fd == -1; addr = addr->ai_next) {
        clientData->outgoing_fd = socket(addr->ai_family, SOCK_NONBLOCK | SOCK_STREAM, addr->ai_protocol);
        if (clientData->outgoing_fd < 0) {
            clientData->outgoing_fd = socket(addr->ai_family, SOCK_STREAM, addr->ai_protocol);
        }
        if (clientData->outgoing_fd < 0) {
            log(ERROR, "Failed to create remote socket on %s", printAddressPort(addr, addrBuffer));
            return STM_ERROR;
        }
        selector_fd_set_nio(clientData->outgoing_fd);
        errno = 0;
        log(DEBUG, "Trying to connect() remote socket to %s", printAddressPort(addr, addrBuffer));
        if (connect(clientData->outgoing_fd, addr->ai_addr, addr->ai_addrlen) == 0 || errno == EINPROGRESS) {
            log(DEBUG, "Successfully connected to: %s (%s %s) %s %s", printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuffer));
            return STM_CONNECT_ATTEMPT;
        } else {
            log(ERROR, "Failed to connect() remote socket to %s: %s", printAddressPort(addr, addrBuffer), strerror(errno));
            close(clientData->outgoing_fd);
            clientData->outgoing_fd = -1;
        }
    }

    log(ERROR, "Failed to connect");
    send(key->fd, "\x05\x04\x00\x00\x00\x00\x00\x00\x00", 10, 0);
    return STM_ERROR;
}

StateSocksv5 stm_request_write(struct selector_key *key) {
    ClientData *clientData = key->data; 
  

}

StateSocksv5 stm_dns_done(struct selector_key *key) {
    ClientData *clientData = key->data; 
    // // TODO(GAGO): aca procesar el dns  
    // int err = 0;
    // socklen_t len = sizeof(err);
    // if (getsockopt(clientData->outgoing_fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
    //     log(ERROR, "connect() failed: %s", strerror(err));
        
    //     //todo chequear si esto esta bien como respuesta de ok
    //     char reply_err[10] = { 
    //         0x05,       // VERSION
    //         0x05,       // REP = connection refused
    //         0x00,       // RSV
    //         0x01, 0,0,0,0,  // ATYP=IPv4 + BND.ADDR = 0.0.0.0
    //         0,0         // BND.PORT = 0
    //     };
    //     send(clientData->client_fd, reply_err, sizeof(reply_err), 0);
    //     close(clientData->outgoing_fd);
    //     return STM_ERROR;
    // }

    // //todo chequear si esto esta bien como respuesta de ok
    // char reply_ok[10] = {
    //     0x05,       
    //     0x00,       // REP = succeeded
    //     0x00,       
    //     0x01, 0,0,0,0, 
    //     0,0        
    // };
    // send(clientData->client_fd, reply_ok, sizeof(reply_ok), 0);

    // selector_set_interest_key(key, OP_READ);
    selector_set_interest(key->s, clientData->client_fd, OP_WRITE);
    if(clientData->connectAddresses == NULL) {
        send(key->fd, "\x05\x04\x00\x00\x00\x00\x00\x00\x00", 10, 0);
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
        log(ERROR, "Failed to getsockname() for remote socket");
        send(key->fd, "\x05\x04\x00\x00\x00\x00\x00\x00\x00", 10, 0);
        return STM_ERROR;
    }

    // Send a server reply: SUCCESS, then send the address to which our socket is bound.
    if (send(key->fd, "\x05\x00\x00", 3, 0) < 0)
        return STM_ERROR;

    switch (boundAddress.ss_family) {
        case AF_INET:
            // Send: '\x01' (ATYP identifier for IPv4) followed by the IP and PORT.
            if (send(key->fd, "\x01", 1, 0) < 0)
                return STM_ERROR;
            if (send(key->fd, &((struct sockaddr_in*)&boundAddress)->sin_addr, 4, 0) < 0)
                return STM_ERROR;
            if (send(key->fd, &((struct sockaddr_in*)&boundAddress)->sin_port, 2, 0) < 0)
                return STM_ERROR;
            break;

        case AF_INET6:
            // Send: '\x04' (ATYP identifier for IPv6) followed by the IP and PORT.
            if (send(key->fd, "\x04", 1, 0) < 0)
                return STM_ERROR;
            if (send(key->fd, &((struct sockaddr_in6*)&boundAddress)->sin6_addr, 16, 0) < 0)
                return STM_ERROR;
            if (send(key->fd, &((struct sockaddr_in6*)&boundAddress)->sin6_port, 2, 0) < 0)
                return STM_ERROR;
            break;

        default:
            // We don't know the address type? Send IPv4 0.0.0.0:0.
            if (send(key->fd, "\x01\x00\x00\x00\x00\x00\x00", 7, 0) < 0)
                return STM_ERROR;
            break;
    }
    clientData->outgoing_fd = sock;
    freeaddrinfo(clientData->connectAddresses);

    selector_set_interest_key(key, OP_READ);
    return STM_CONNECTION_TRAFFIC;
}