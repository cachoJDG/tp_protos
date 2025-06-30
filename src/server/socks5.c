#include "socks5.h"
#include "sockRequest.h"
#include "connectionTraffic.h"

fd_handler CLIENT_HANDLER = {
    .handle_read = client_handler_read,
    .handle_write = client_handler_write,
    .handle_block = client_handler_block,
    .handle_close = client_handler_close,
};

static const struct state_definition CLIENT_STATE_TABLE[] = {
    {
        .state = STM_INITIAL_READ, // https://datatracker.ietf.org/doc/html/rfc1928#section-3
        .on_arrival = stm_initial_read_arrival,
        .on_read_ready = stm_initial_read,
        .on_write_ready = error_redirect,
        .on_block_ready = error_redirect,
    },
    {
        .state = STM_INITIAL_WRITE,
        .on_read_ready = error_redirect,
        .on_write_ready = stm_initial_write,
        .on_block_ready = error_redirect,
    }, 
    {
        .state = STM_LOGIN_READ, // https://datatracker.ietf.org/doc/html/rfc1929
        .on_arrival = stm_login_read_arrival,
        .on_read_ready = stm_login_read,
        .on_write_ready = error_redirect,
        .on_block_ready = error_redirect,
    },
    {
        .state = STM_LOGIN_WRITE,
        .on_read_ready = error_redirect,
        .on_write_ready= stm_login_write,
        .on_block_ready = error_redirect,
    },
    {
        .state = STM_REQUEST_READ, // https://datatracker.ietf.org/doc/html/rfc1928#section-4
        .on_arrival = stm_request_read_arrival,
        .on_read_ready = stm_request_read,
        .on_write_ready = error_redirect,
        .on_block_ready = error_redirect,
    },
    {
        .state = STM_REQUEST_WRITE, // https://datatracker.ietf.org/doc/html/rfc1928#section-4
        .on_read_ready = error_redirect,
        .on_write_ready = stm_request_write,
        .on_block_ready = error_redirect,

    },
    {
        .state = STM_CONNECT_ATTEMPT, // https://datatracker.ietf.org/doc/html/rfc1928#section-4
        .on_arrival = stm_connect_attempt_arrival,
        .on_read_ready = error_redirect,
        .on_write_ready = stm_connect_attempt_write,
        .on_block_ready = error_redirect,
    },
    {
        .state = STM_CONNECTION_TRAFFIC, // se termino de establecer la conexion. y ahora se pasan los datos
        .on_arrival = stm_connection_traffic_arrival,
        .on_write_ready = stm_connection_traffic_write,
        .on_read_ready = stm_connection_traffic_read,
        .on_departure = stm_connection_traffic_departure,
        .on_block_ready = error_redirect, // Creo que este estado deberíamos manejarlo
    },
    {
        .state = STM_DNS_DONE, 
        // TODO: OJO que este estado genera bugs cuando se hace read o write. Los error_redirect ayudan a "prevenir" esto, pero no sé si está bien
        .on_read_ready = error_redirect, 
        .on_write_ready = error_redirect,
        .on_block_ready = stm_dns_done,
    },
    {
        .state = STM_DONE, 
        .on_arrival = stm_done_arrival, 
    },
    {
        .state = STM_ERROR, 
        .on_arrival = stm_error, 
    },
};

static int acceptTCPConnection(int servSock) {
	struct sockaddr_storage clntAddr;
	socklen_t clntAddrLen = sizeof(clntAddr);
    static char addrBuffer[MAX_ADDR_BUFFER];

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

void handle_read_passive(struct selector_key *key) {
    int clientSocket = acceptTCPConnection(key->fd);
    log(DEBUG, "Accepted new client connection on socket %d", clientSocket);

    ClientData *clientData = calloc(1, sizeof(ClientData)); 
    
    clientData->stm.initial = STM_INITIAL_READ;
    clientData->stm.max_state = STM_ERROR;
    clientData->stm.states = CLIENT_STATE_TABLE;
    clientData->client_fd   = clientSocket;
    clientData->outgoing_fd = -1;
    stm_init(&clientData->stm);
    buffer_init(&clientData->client_buffer, BUFSIZE, clientData->clientBufferData);

    selector_register(key->s, clientSocket, &CLIENT_HANDLER, OP_READ, (void *)clientData);
}

void stm_initial_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
}

StateSocksv5 stm_initial_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    log(DEBUG, "stm_initial_read called for socket %d", key->fd);
    size_t bufferLimit = 0;
    uint8_t *clientBuffer = buffer_write_ptr(&clientData->client_buffer, &bufferLimit);
    ssize_t bytesRead = recv(key->fd, clientBuffer, bufferLimit, 0);
    if(bytesRead <= 0) {
        return STM_ERROR;
    }

    buffer_write_adv(&clientData->client_buffer, bytesRead);
    uint8_t socksVersion = buffer_read(&clientData->client_buffer);
    uint8_t methodCount = buffer_read(&clientData->client_buffer);

    clientData->authMethod = AUTH_NO_ACCEPTABLE;
    for(int i = 0; i < methodCount; i++) {
        AuthMethod authMethod = buffer_read(&clientData->client_buffer);
        if(authMethod == AUTH_USER_PASSWORD) {
            clientData->authMethod = AUTH_USER_PASSWORD;
            break;
        }
        else if(authMethod == AUTH_NONE) {
            clientData->authMethod = AUTH_NONE;
        }
    }
    char *authStr = (clientData->authMethod == AUTH_USER_PASSWORD) ? "user password" 
                  : ((clientData->authMethod == AUTH_NONE) ? "none" : "invalid");
    log(DEBUG, "version=%d method='%s'", socksVersion, authStr);

    selector_set_interest_key(key, OP_WRITE); 

    return STM_INITIAL_WRITE;
}

StateSocksv5 error_redirect(struct selector_key *key) {
    log(ERROR, "error_redirect called for socket %d", key->fd);
    ClientData *clientData = key->data;
    return STM_ERROR;
}

StateSocksv5 stm_initial_write(struct selector_key *key) {
    log(DEBUG, "stm_initial_write called for socket %d", key->fd);
    ClientData *clientData = key->data;
    
    switch (clientData->authMethod)
    {
    case AUTH_NONE:
        send(key->fd, "\x05\x00", 2, 0);
        selector_set_interest_key(key, OP_READ); 
        return STM_REQUEST_READ;
    case AUTH_USER_PASSWORD:
        send(key->fd, "\x05\x02", 2, 0);
        selector_set_interest_key(key, OP_READ); 
        return STM_LOGIN_READ;
    case AUTH_GSSAPI:
    default:
        return STM_ERROR;
    }
}

void stm_login_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
}

StateSocksv5 stm_login_read(struct selector_key *key) {
    log(DEBUG, "stm_login_read called for socket %d", key->fd);
    ClientData *clientData = key->data;
    char password[USERNAME_MAX_LENGTH] = {0};
    size_t bufferLimit = 0;
    uint8_t *clientBuffer = buffer_write_ptr(&clientData->client_buffer, &bufferLimit);
    ssize_t bytesRead = recv(key->fd, clientBuffer, bufferLimit, 0);

    buffer_write_adv(&clientData->client_buffer, bytesRead);
    uint8_t loginVersion = buffer_read(&clientData->client_buffer);
    if(loginVersion != SOCKS_LOGIN_VERSION) {
        log(ERROR, "invalid login version %d", loginVersion);
        return STM_ERROR;
    }
    uint8_t usernameLen = buffer_read(&clientData->client_buffer);
    buffer_read_bytes(&clientData->client_buffer, clientData->username, usernameLen);
    clientData->username[usernameLen] = '\0';

    uint8_t passwordLen = buffer_read(&clientData->client_buffer);
    buffer_read_bytes(&clientData->client_buffer, password, passwordLen);
    log(DEBUG, "username[%d]='%s' password[%d]='%s'", usernameLen, clientData->username, passwordLen, password);

    selector_set_interest_key(key, OP_WRITE); 
    return STM_LOGIN_WRITE;
}

StateSocksv5 stm_login_write(struct selector_key *key) {
    log(DEBUG, "stm_login_write called for socket %d", key->fd);
    ClientData *clientData = key->data;
    
    ssize_t bytes = send(key->fd, "\x05\x00", 2, 0);
    // ssize_t bytes = send(key->fd, "\x05\x01", 2, 0); // si esta mal el usuario

    selector_set_interest_key(key, OP_READ); 
    return STM_REQUEST_READ;
}

void stm_error(unsigned state, struct selector_key *key) {
    log(ERROR, "stm_error called for socket %d", key->fd);
    ClientData *clientData = key->data; 
    log(ERROR, ".");
    selector_set_interest_key(key, OP_NOOP);
}

void stm_done_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    log(DEBUG, "done");

    close(clientData->client_fd);
    
}

void client_handler_read(struct selector_key *key) {
    log(DEBUG, "client_handler_read called for socket %d", key->fd);
    ClientData *clientData = key->data;
    StateSocksv5 state = stm_handler_read(&clientData->stm, key);
    if(state == STM_ERROR || state == STM_DONE) {
        selector_unregister_fd(key->s, key->fd);
    }
}

void client_handler_write(struct selector_key *key) {
    log(DEBUG, "client_handler_write called for socket %d", key->fd);
    ClientData *clientData = key->data;
    StateSocksv5 state = stm_handler_write(&clientData->stm, key);
    if(state == STM_ERROR || state == STM_DONE) {
        selector_unregister_fd(key->s, key->fd);
    }
}
void client_handler_block(struct selector_key *key) {
    log(DEBUG, "client_handler_block called for socket %d", key->fd);
    ClientData *clientData = key->data;
    StateSocksv5 state = stm_handler_block(&clientData->stm, key);
    if(state == STM_ERROR || state == STM_DONE) {
        selector_unregister_fd(key->s, key->fd);
    }
}
void client_handler_close(struct selector_key *key) {

    // enum StateSocksv5 state = stm_handler_close(&clientData->stm, key); // este no retorna xd
    // TODO: avoid double free
    // selector_set_interest_key(key, OP_NOOP);
    free(key->data);
    key->data = NULL; // Evitar que se intente liberar de nuevo
    log(INFO, "handling client close");
    close(key->fd); // Cerrar el socket del cliente
}