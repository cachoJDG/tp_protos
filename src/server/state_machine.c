#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "../shared/util.h"
#include "dns_resolver.h"

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
    }
    free(job);
    selector_notify_block(job->selector, job->client_fd);
    return NULL;
}

void stm_initial_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    memset(clientData->buffer, 0, sizeof(clientData->buffer));
}

StateSocksv5 stm_initial_read_version(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[0], 1, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    log(DEBUG, "Received SOCKS version: %d", clientData->buffer[0]);
    return STM_INITIAL_READ_METHOD_COUNT;
}
StateSocksv5 stm_initial_read_method_count(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[1], 1, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    log(DEBUG, "Received SOCKS method count: %d", clientData->buffer[1]);
    clientData->to_read = clientData->buffer[1];
    return STM_INITIAL_READ_METHODS;
}
StateSocksv5 stm_initial_read_methods(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[2], clientData->to_read, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    clientData->to_read -= bytesRead;
    if (clientData->to_read > 0) {
        log(DEBUG, "Waiting for more data, %zd bytes remaining", clientData->to_read);
        return STM_INITIAL_READ_METHODS; // Esperamos más datos
    }
    log(DEBUG, "Received SOCKS methods: ");
    for (size_t i = 0; i < clientData->buffer[1]; i++) {
        log(DEBUG, "  Method %zu: %d", i, clientData->buffer[2 + i]);
    }
    selector_set_interest_key(key, OP_WRITE);
    return STM_INITIAL_WRITE;
}

StateSocksv5 stm_initial_write(struct selector_key *key) {
    ClientData *clientData = key->data;

    ssize_t bytes = send(key->fd, "\x05\x02", 2, 0); // 0x02 = LOGIN
    selector_set_interest_key(key, OP_READ); 
    return STM_LOGIN_READ_VERSION;

    // TODO: falta el caso de que el cliente haya seleccionado METHOD=NONE=0x00
    // return STM_REQUEST_READ;
}

void stm_login_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    memset(clientData->buffer, 0, sizeof(clientData->buffer));
}

StateSocksv5 stm_login_read_version(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[0], 1, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    log(DEBUG, "Received SOCKS version: %d", clientData->buffer[0]);
    return STM_LOGIN_READ_USER_COUNT;
}

StateSocksv5 stm_login_read_user_count(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->user_length, 1, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    clientData->to_read = clientData->user_length;

    log(DEBUG, "Received SOCKS username length: %d", clientData->user_length);
    return STM_LOGIN_READ_USER;
}

StateSocksv5 stm_login_read_user(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->username[0], clientData->to_read, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    clientData->to_read -= bytesRead;
    if (clientData->to_read > 0) {
        log(DEBUG, "Waiting for more data, %zd bytes remaining", clientData->to_read);
        return STM_LOGIN_READ_USER; // Esperamos más datos
    }
    clientData->username[clientData->user_length] = '\0'; // Null-terminate the username
    log(DEBUG, "Received SOCKS username: %s", clientData->username);
    return STM_LOGIN_READ_PASS_COUNT;
}

StateSocksv5 stm_login_read_pass_count(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->pass_length, 1, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    clientData->to_read = clientData->pass_length;
    log(DEBUG, "Received SOCKS password length: %d", clientData->pass_length);

    return STM_LOGIN_READ_PASS;
}

StateSocksv5 stm_login_read_pass(struct selector_key *key) {
    ClientData *clientData = key->data;
    // TODO: muy importante chequear overflow de buffer en todos los casos
    ssize_t bytesRead = recv(key->fd, &clientData->password[0], clientData->to_read, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    clientData->to_read -= bytesRead;
    if (clientData->to_read > 0) {
        log(DEBUG, "Waiting for more data, %zd bytes remaining", clientData->to_read);
        return STM_LOGIN_READ_PASS; // Esperamos más datos
    }
    clientData->password[clientData->pass_length] = '\0'; // Null-terminate the password
    log(DEBUG, "Received SOCKS password: %.*s", (int)clientData->pass_length, &clientData->password[0]);
    selector_set_interest_key(key, OP_WRITE);
    return STM_LOGIN_WRITE;
}

StateSocksv5 stm_login_write(struct selector_key *key) {
    ClientData *clientData = key->data;

    ssize_t bytes = send(key->fd, "\x05\x00", 2, 0); // 0x00 = SUCCESS
    if (bytes <= 0) {
        return STM_ERROR;
    }
    selector_set_interest_key(key, OP_READ); 
    return STM_REQUEST_READ_VERSION;
}

void stm_request_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    memset(clientData->buffer, 0, sizeof(clientData->buffer));
    
}

StateSocksv5 stm_request_read_version(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[0], 1, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
        // TODO: Ojo que está ignorando la versión (debería rechazar si la versión es incorrecta)
    // Para rechazar deberíamos mandar un mensaje que diga "05 Connection Refused"
    log(DEBUG, "Received SOCKS version: %d", clientData->buffer[0]);
    return STM_REQUEST_READ_CMD;
}

StateSocksv5 stm_request_read_cmd(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[1], 1, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    log(DEBUG, "Received SOCKS command: %d", clientData->buffer[1]);
    if (clientData->buffer[1] != 0x01) { // 0x01 = CONNECT
        log(ERROR, "Unsupported SOCKS command: %d", clientData->buffer[1]);
                    send(key->fd, "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return STM_ERROR;
    }
    return STM_REQUEST_READ_RESERVED;
}

StateSocksv5 stm_request_read_reserved(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[2], 1, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
     // TODO: QUIZA CHEQUEAR QUE VALGA 0x00
    log(DEBUG, "Received SOCKS reserved byte: %d", clientData->buffer[2]);
    return STM_REQUEST_READ_ATYP;
}

StateSocksv5 stm_request_read_atyp(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[3], 1, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    log(DEBUG, "Received SOCKS address type: %d", clientData->buffer[3]);
    
    clientData->addressType = clientData->buffer[3];

    switch (clientData->addressType) {
        case 0x01: // IPv4
            clientData->to_read = 4; // 4 bytes for IPv4 address
            return STM_REQUEST_READ_IPV4;
        case 0x03: // Domain name
            return STM_REQUEST_READ_DOMAIN_NAME_SIZE;
        case 0x04: // IPv6
            clientData->to_read = 16; // 16 bytes for IPv6 address
            return STM_REQUEST_READ_IPV6;
        default:
            log(ERROR, "Unsupported address type: %d", clientData->buffer[3]);
            return STM_ERROR;
    }
    return STM_ERROR; // Should not reach here
}

StateSocksv5 stm_request_read_ipv4(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[4], clientData->to_read, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    clientData->to_read -= bytesRead;
    if (clientData->to_read > 0) {
        log(DEBUG, "Waiting for more data, %zd bytes remaining", clientData->to_read);
        return STM_REQUEST_READ_IPV4; // Esperamos más datos
    }
    memcpy(&clientData->ipv4_addr, &clientData->buffer[4], 4);

    log(DEBUG, "Received SOCKS IPv4 address: %d.%d.%d.%d", 
        clientData->buffer[4], clientData->buffer[5], 
        clientData->buffer[6], clientData->buffer[7]);
    
    return STM_REQUEST_READ_PORT;
}

StateSocksv5 stm_request_read_domain_name_size(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[4], 1, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    log(DEBUG, "Received SOCKS domain name size: %d", clientData->buffer[4]);
    clientData->to_read = clientData->buffer[4];
    return STM_REQUEST_READ_DOMAIN_NAME;
}

StateSocksv5 stm_request_read_domain_name(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[5], clientData->to_read, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    clientData->to_read -= bytesRead;
    if (clientData->to_read > 0) {
        log(DEBUG, "Waiting for more data, %zd bytes remaining", clientData->to_read);
        return STM_REQUEST_READ_DOMAIN_NAME; // Esperamos más datos
    }
    memcpy(clientData->unresolved_hostname, &clientData->buffer[5], clientData->buffer[4]);
    clientData->unresolved_hostname[clientData->buffer[4]] = '\0'; // Null-terminate the hostname

    log(DEBUG, "Received SOCKS domain name: %.*s", clientData->buffer[4], &clientData->buffer[5]);
    return STM_REQUEST_READ_PORT;
}

StateSocksv5 stm_request_read_ipv6(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[4], 16, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    clientData->to_read -= bytesRead;
    if (clientData->to_read > 0) {
        log(DEBUG, "Waiting for more data, %zd bytes remaining", clientData->to_read);
        return STM_REQUEST_READ_IPV6; // Esperamos más datos
    }
    memcpy(&clientData->ipv6_addr, &clientData->buffer[4], 16);
    log(DEBUG, "Received SOCKS IPv6 address");
    return STM_REQUEST_READ_PORT;
}

StateSocksv5 stm_request_read_port(struct selector_key *key) {
    ClientData *clientData = key->data;
    ssize_t bytesRead = recv(key->fd, &clientData->buffer[20], 2, 0);
    if (bytesRead <= 0) {
        return STM_ERROR;
    }
    clientData->destinationPort = ntohs(*(uint16_t *)&clientData->buffer[20]);

    char hostname[MAX_ADDR_BUFFER + 1] = {0};
    struct addrinfo addrHints;
    memset(&addrHints, 0, sizeof(addrHints));
    addrHints.ai_socktype = SOCK_STREAM;
    addrHints.ai_protocol = IPPROTO_TCP;



    switch (clientData->addressType) {
        case 0x01: // IPv4
            addrHints.ai_family = AF_INET;
            inet_ntop(AF_INET, &clientData->ipv4_addr, hostname, INET_ADDRSTRLEN);
            break;
        case 0x03: // Domain name
        {
            DnsJob *job = calloc(1, sizeof(*job));
            if (!job) {
                log(ERROR, "malloc: %s", strerror(errno));
                return STM_ERROR;
            }
            strcpy(job->host, clientData->unresolved_hostname);

            pthread_t tid;
            snprintf(job->service, sizeof(job->service) - 1, "%u", clientData->destinationPort);

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

            break;
        case 0x04: // IPv6
            addrHints.ai_family = AF_INET6;
            inet_ntop(AF_INET6, &clientData->ipv6_addr, hostname, INET6_ADDRSTRLEN);
            break;
        default:
            log(ERROR, "Unknown address type: %d", clientData->addressType);
            // The reply specified REP as X'08' "Address type not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
            send(key->fd, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
            return STM_ERROR;
    }

    char service[6] = {0};
    sprintf(service, "%d", clientData->destinationPort);
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
    log(DEBUG, "cmd=%d addressType=%d destinationPort=%u", clientData->cmd, clientData->addressType, clientData->destinationPort);

    selector_set_interest_key(key, OP_WRITE); 

    return STM_REQUEST_WRITE;
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
    freeaddrinfo(clientData->connectAddresses);

    selector_set_interest_key(key, OP_READ);
    return STM_CONNECTION_TRAFFIC;
}

void stm_error(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data; 
    ssize_t bytes = recv(key->fd, clientData->buffer, BUFSIZE, 0);
    log(ERROR, "bytes recibidos: ");
    // print de bytes comentado porque puede imprimir bytes infinitos
    // print_hex(clientData->buffer, bytes);
    selector_set_interest_key(key, OP_NOOP);
}

void stm_done_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    log(DEBUG, "done");

    close(clientData->client_fd);
    
}

