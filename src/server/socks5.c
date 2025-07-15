#include "socks5.h"
#include "sockRequest.h"
#include "connectionTraffic.h"
#include "sockUtils.h"
#include "../users/users.h"
#include "initialParser.h"
#include "../monitoring/monitoringMetrics.h"

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
        .on_write_ready = stm_initial_write,
        .on_read_ready = error_redirect,
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
        .on_write_ready= stm_login_write,
        .on_read_ready = error_redirect,
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
        .on_write_ready = stm_request_write,
        .on_read_ready = error_redirect,
        .on_block_ready = error_redirect,
    },
    {
        .state = STM_CONNECT_ATTEMPT, // https://datatracker.ietf.org/doc/html/rfc1928#section-4
        .on_arrival = stm_connect_attempt_arrival,
        .on_write_ready = stm_connect_attempt_write,
        .on_read_ready = error_redirect,
        .on_block_ready = error_redirect,
    },
    {
        .state = STM_CONNECTION_TRAFFIC, // se termino de establecer la conexion. y ahora se pasan los datos
        .on_arrival = stm_connection_traffic_arrival,
        .on_write_ready = stm_connection_traffic_write,
        .on_read_ready = stm_connection_traffic_read,
        .on_departure = stm_connection_traffic_departure,
        .on_block_ready = error_redirect, 
    },
    {
        .state = STM_ERROR_MSG_WRITE,
        .on_write_ready = stm_error_msg_write,
        .on_read_ready = error_redirect,
        .on_block_ready = error_redirect,
    },
    {
        .state = STM_DNS_DONE, 
        .on_block_ready = stm_dns_done,
        // .on_read_ready = error_redirect,
        // .on_write_ready = error_redirect,
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
    char addrBuffer[MAX_ADDR_BUFFER] = {0};

	// Wait for a client to connect
	int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
	if (clntSock < 0) {
		return -1;
	}
    if(selector_fd_set_nio(clntSock < 0)) {
        return -1;
    }

	printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);
	log(DEBUG, "Handling client %s", addrBuffer);

	return clntSock;
}

void handle_read_passive(struct selector_key *key) {
    int clientSocket = acceptTCPConnection(key->fd);
    if(clientSocket == -1) {
        return;
    }
    if(clientSocket >= SELECTOR_CAPACITY_PROXY) {
        log(DEBUG, "se rechazo al cliente con fd=%d", clientSocket);
        close(clientSocket);
        return;
    }
    
    ClientData *clientData = calloc(1, sizeof(ClientData)); 
    
    clientData->stm.initial = STM_INITIAL_READ;
    clientData->stm.max_state = STM_ERROR;
    clientData->stm.states = CLIENT_STATE_TABLE;
    clientData->client_fd   = clientSocket;
    clientData->outgoing_fd = -1;
    stm_init(&clientData->stm);
    buffer_init(&clientData->client_buffer, BUFSIZE, clientData->clientBufferData);
    buffer_init(&clientData->outgoing_buffer, BUFSIZE, clientData->remoteBufferData);
    
    if(selector_register(key->s, clientSocket, &CLIENT_HANDLER, OP_READ, (void *)clientData)) {
        log(DEBUG, "selector register failed: se rechazo al cliente con fd=%d", clientSocket);
        free(clientData);
        close(clientSocket);
        return;
    }
    metrics_increment_connections();
}

void stm_initial_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    ini_initialize(&clientData->initialParserInfo, &clientData->toRead);
    buffer_reset(&clientData->client_buffer);
}

// ---------- Funciones Auxiliares ---------- (TODO: mover a otro lado)

// Esto asegura de que SOLAMENTE se haga recv de lo que se pueda recibir
// y que no se intente leer más de lo que el buffer puede contener.
ssize_t recv_ToBuffer_WithMetrics(int fd, buffer *buffer, ssize_t toRead) {
    ssize_t bufferLimit = 0;
    uint8_t *writePtr = buffer_write_ptr(buffer, (size_t*)&bufferLimit);

    ssize_t maxToRead = (bufferLimit > toRead) ? toRead : bufferLimit;
    ssize_t bytesRead = recvBytesWithMetrics(fd, writePtr, maxToRead, 0);
    if (bytesRead > 0) {
        buffer_write_adv(buffer, bytesRead);
    }
    return bytesRead;
}

ssize_t send_FromBuffer_WithMetrics(int fd, buffer *buffer, ssize_t toWrite) {
    ssize_t bufferLimit = 0;
    uint8_t *writePtr = buffer_read_ptr(buffer, (size_t *)&bufferLimit);

    ssize_t maxToWrite = (bufferLimit > toWrite) ? toWrite : bufferLimit;
    ssize_t bytesWritten = sendBytesWithMetrics(fd, writePtr, maxToWrite, 0);
    if (bytesWritten > 0) {
        buffer_read_adv(buffer, bytesWritten);
    }
    return bytesWritten;
}

void response_ToBuffer(buffer *outgoingBuffer, char *response, size_t responseSize) {
    buffer_reset(outgoingBuffer);
    size_t someVariableThatPreventsErrors = 0;
    uint8_t *writePtr = buffer_write_ptr(outgoingBuffer, &someVariableThatPreventsErrors);
    memcpy(writePtr, response, responseSize);
    buffer_write_adv(outgoingBuffer, responseSize);
    return;
}

StateSocksv5 prepare_error(struct selector_key *key, char *response, size_t responseSize) {
    ClientData *clientData = key->data;
    response_ToBuffer(&clientData->outgoing_buffer, response, responseSize);
    clientData->toWrite = responseSize;
    selector_set_interest_key(key, OP_WRITE);
    return STM_ERROR_MSG_WRITE;
}

StateSocksv5 write_everything(struct selector_key *key, StateSocksv5 currentState, fd_interest nextInterest, StateSocksv5 nextState) {
    ClientData *clientData = key->data;
    
    // 1. Leo del buffer
    ssize_t bytesWritten = send_FromBuffer_WithMetrics(key->fd, &clientData->outgoing_buffer, clientData->toWrite);

    // 1,5. Manejo de errores [WRITE]
    if (bytesWritten <= 0) {
        if (bytesWritten == 0) {
            log(DEBUG, "Failed to write request data to client fd=%d: Unknown Error", key->fd);
            return STM_DONE; // No se cierra el socket, solo se marca como cerrado
        }
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            errno = 0;
            return currentState; // No se pudo escribir, pero no hubo error
        }
        log(DEBUG, "Failed to write request data to client fd=%d: %s", key->fd, strerror(errno));
        errno = 0;
        selector_set_interest_key(key, OP_NOOP);
        return STM_DONE;
    }

    // 2. Repito hasta vaciar el buffer
    clientData->toWrite -= bytesWritten;
    if (clientData->toWrite > 0) {
        return currentState;
    }

    // 3. Cambio de estado
    selector_set_interest_key(key, nextInterest);
    return nextState;
}

// ---------- Fin de: Funciones Auxiliares ----------

StateSocksv5 stm_initial_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    socks5_initial_parserinfo* parserInfo = &clientData->initialParserInfo;

    // 1. Guardo datos en el buffer (sin que se lean bytes de más)
    ssize_t bytesRead = recv_ToBuffer_WithMetrics(key->fd, &clientData->client_buffer, clientData->toRead);

    // 1,5. Manejo de errores [READ]
    if(bytesRead <= 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            errno = 0;
            return STM_INITIAL_READ; // No se pudo leer, pero no hubo error
        }
        if (bytesRead == 0) {
            log(INFO, "Connection closed by peer [CLIENT] on socket %d", key->fd);
            selector_set_interest_key(key, OP_NOOP);
            return STM_DONE; // No se cierra el socket, solo se marca como cerrado
        }
        log(DEBUG, "Failed to read initial data from client fd=%d: %s", key->fd, strerror(errno));
        errno = 0;
        return STM_DONE;
    }

    // 2. Parsing (de lo que hay en el buffer)
    clientData->toRead -= bytesRead;
    switch(ini_parse(&clientData->client_buffer, parserInfo, &clientData->toRead)) {
        case PARSER_OK:
            break; // Termino el parsing
        case PARSER_INCOMPLETE:
            return STM_INITIAL_READ; // No se recibieron todos los bytes necesarios
        case PARSER_ERROR:
            response_ToBuffer(&clientData->outgoing_buffer, "\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00", 10);
            clientData->toWrite = 10;
            selector_set_interest_key(key, OP_WRITE);
            return STM_ERROR_MSG_WRITE;
    }

    // 3. Acciones
    uint8_t socksVersion = parserInfo->socksVersion;
    uint8_t methodCount = parserInfo->methodCount;

    clientData->authMethod = AUTH_NO_ACCEPTABLE;
    for(int i = 0; i < methodCount; i++) {
        AuthMethod authMethod = parserInfo->authMethods[i];
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

    // 4. Preparo buffers para la respuesta
    buffer_reset(&clientData->outgoing_buffer);
    buffer_write(&clientData->outgoing_buffer, 0x05); // SOCKS version 5
    switch (clientData->authMethod) {
        case AUTH_NONE:
            buffer_write(&clientData->outgoing_buffer, 0x00); // No authentication required
            break;
        case AUTH_USER_PASSWORD:
            buffer_write(&clientData->outgoing_buffer, 0x02); // User/password authentication
            break;
        case AUTH_GSSAPI:
        default:
            log(DEBUG, "Unsupported authentication method %d", clientData->authMethod);
            return prepare_error(key, "\x05\xFF", 2);
    }
    clientData->toWrite = 2;

    selector_set_interest_key(key, OP_WRITE); 
    return STM_INITIAL_WRITE;
}

StateSocksv5 stm_initial_write(struct selector_key *key) {
    ClientData *clientData = key->data;

    switch(clientData->authMethod) {
        case AUTH_USER_PASSWORD:
            return write_everything(key, STM_INITIAL_WRITE, OP_READ, STM_LOGIN_READ);
        case AUTH_NONE:
            return write_everything(key, STM_INITIAL_WRITE, OP_READ, STM_REQUEST_READ);
        default:
            break;
    }
    log(DEBUG, "Unsupported authentication method %d", clientData->authMethod);
    return prepare_error(key, "\x05\xFF", 2);
}

void stm_login_read_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;
    login_initialize(&clientData->loginParserInfo, &clientData->toRead);
    buffer_reset(&clientData->client_buffer);
}

StateSocksv5 stm_login_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    socks5_login_parserinfo* parserInfo = &clientData->loginParserInfo;

    // 1. Guardo datos en el buffer (sin que se lean bytes de más)
    ssize_t bytesRead = recv_ToBuffer_WithMetrics(key->fd, &clientData->client_buffer, clientData->toRead);

    // 1,5. Manejo de errores [READ]
    if(bytesRead <= 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            errno = 0;
            return STM_LOGIN_READ; // No se pudo leer, pero no hubo error
        }
        if (bytesRead == 0) {
            log(DEBUG, "Connection closed by peer [CLIENT] on socket %d", key->fd);
            selector_set_interest_key(key, OP_NOOP);
            return STM_DONE; // No se cierra el socket, solo se marca como cerrado
        }
        log(ERROR, "Failed to read login data from client fd=%d: %s", key->fd, strerror(errno));
        errno = 0;
        return STM_DONE;
    }

    // 2. Parsing (de lo que hay en el buffer)
    clientData->toRead -= bytesRead;
    switch(login_parse(&clientData->client_buffer, parserInfo, &clientData->toRead)) {
        case PARSER_OK:
            break; // Termino el parsing
        case PARSER_INCOMPLETE:
            return STM_LOGIN_READ; // No se recibieron todos los bytes necesarios
        case PARSER_ERROR:
            return prepare_error(key, "\x05\x01\x00\x01\x00\x00\x00\x00\x00", 10);
    }

    // 3. Acciones
    char username[NAME_MAX_LENGTH] = {0};
    memcpy(username, parserInfo->username, parserInfo->usernameLength);
    for (int i = 0; i < 256 && username[i]; i++) {
        if (username[i] < ' ') {
            username[i] = '\0';
            break;
        }
    }
    username[parserInfo->usernameLength] = '\0';
    char password[NAME_MAX_LENGTH] = {0};
    memcpy(password, parserInfo->password, parserInfo->passwordLength);
    password[parserInfo->passwordLength] = '\0';
    uint8_t loginVersion = parserInfo->loginVersion;

    if(loginVersion != SOCKS_LOGIN_VERSION) {
        log(DEBUG, "Invalid login version %d", loginVersion);
        return prepare_error(key, "\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00", 10);
    }

    if(validate_login(username, password)) {
        log(DEBUG, "Login successful for user '%s'", username);
        memcpy(clientData->username, username, NAME_MAX_LENGTH);
        clientData->isLoggedIn = 1;
    } else {
        log(INFO, "Login failed for user '%s'", username);
        clientData->isLoggedIn = 0;
    }

    // 4. Preparo buffers para la respuesta
    buffer_reset(&clientData->outgoing_buffer);
    size_t bufferLimit = 0;
    uint8_t *response = buffer_write_ptr(&clientData->outgoing_buffer, &bufferLimit);
    response[0] = 0x05;
    if(clientData->isLoggedIn) {
        response[1] = 0x00;
    } else {
        response[1] = 0x01;
    }
    buffer_write_adv(&clientData->outgoing_buffer, 2);
    clientData->toWrite = 2;
    selector_set_interest_key(key, OP_WRITE);
    return STM_LOGIN_WRITE;
}

StateSocksv5 stm_login_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    if (clientData->isLoggedIn) {
        return write_everything(key, STM_LOGIN_WRITE, OP_READ, STM_REQUEST_READ);
    } else {
        log(DEBUG, "Log in failed %d", clientData->authMethod);
        return prepare_error(key, "\x05\x01\x00\x01\x00\x00\x00\x00\x00", 10);
    }
}

StateSocksv5 stm_error_msg_write(struct selector_key *key) {
    return write_everything(key, STM_ERROR_MSG_WRITE, OP_NOOP, STM_DONE);
}

void stm_error(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data; 
    selector_set_interest_key(key, OP_NOOP);
    log(DEBUG, "error called for socket %d, state=%d", key->fd, clientData->stm.current->state);
}

void stm_done_arrival(unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data;

    close(clientData->client_fd);
    
}

void client_handler_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    StateSocksv5 state = stm_handler_read(&clientData->stm, key);
    if(state == STM_ERROR || state == STM_DONE) {
        if(clientData->outgoing_fd != -1) {
            selector_unregister_fd(key->s, clientData->outgoing_fd);
        }
        selector_unregister_fd(key->s, key->fd);
    }
}

void client_handler_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    StateSocksv5 state = stm_handler_write(&clientData->stm, key);
    if(state == STM_ERROR || state == STM_DONE) {
        if(clientData->outgoing_fd != -1) {
            selector_unregister_fd(key->s, clientData->outgoing_fd);
        }
        selector_unregister_fd(key->s, key->fd);
    }
}
void client_handler_block(struct selector_key *key) {
    ClientData *clientData = key->data;
    StateSocksv5 state = stm_handler_block(&clientData->stm, key);
    if(state == STM_ERROR || state == STM_DONE) {
        if(clientData->outgoing_fd != -1) {
            selector_unregister_fd(key->s, clientData->outgoing_fd);
        }
        selector_unregister_fd(key->s, key->fd);
    }
}
void client_handler_close(struct selector_key *key) {
    ClientData *clientData = key->data;
    if(clientData->client_fd != -1) {
        close(clientData->client_fd);
    }
    if(clientData->connectAddresses) {
        freeaddrinfo(clientData->connectAddresses);
    }

    free(key->data);
    key->data = NULL; // Evitar que se intente liberar de nuevo
    closeSocketWithMetrics(key->fd); // Cerrar el socket del cliente
}

StateSocksv5 error_redirect(struct selector_key *key) {
    ClientData *clientData = key->data;
    log(ERROR, "error_redirect called for socket %d, state=%d", key->fd, clientData->stm.current->state);
    return STM_ERROR;
}