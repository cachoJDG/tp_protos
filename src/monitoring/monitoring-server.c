#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include "../shared/logger.h"
#include "../shared/util.h"
#include "../parser.h"
#include <signal.h>
#include "../users/users.h"
#include <stdlib.h>
#include "monitoring-server.h"
#include "monitoringServerUtils.h"

#define MAXPENDING 5
#define BUFSIZE_MONITORING 512
#define MAX_ADDR_BUFFER_MONITORING 128
#define SELECTOR_CAPACITY 256

static char addrBuffer[MAX_ADDR_BUFFER_MONITORING];
struct sockaddr_storage _localAddr;

int acceptTCPConnection(int servSock) {
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

ssize_t recv_to_monitoring_buffer(int fd, buffer *buf, ssize_t maxBytes) {
    size_t available;
    uint8_t *writePtr = buffer_write_ptr(buf, &available);
    
    ssize_t toRead = (maxBytes < available) ? maxBytes : available;
    
    if (toRead <= 0) {
        return 0;
    }
    
    ssize_t bytesRead = recv(fd, writePtr, toRead, 0);
    if (bytesRead > 0) {
        buffer_write_adv(buf, bytesRead);
    }
    return bytesRead;
}

void print_hex_compact(const char* label, const unsigned char* buffer, size_t length) {
    if (current_level <= DEBUG) {
        printf("%s (%zu bytes): ", label, length);
        for (size_t i = 0; i < length; i++) {
            printf("%02X", buffer[i]);
            if (i < length - 1) printf(" ");
        }
        printf("\n");
    }
}

void stm_read_monitoring_arrival(unsigned state, struct selector_key *key) {
    MonitoringClientData *clientData = key->data;
    
    // In case of a new connection, reset the buffer
    if (state == STM_LOGIN_MONITORING_READ) {
        buffer_reset(&clientData->client_buffer);
        clientData->toRead = 1;
        clientData->parsing_state = 0;
    }
    
    log(DEBUG, "Entering state %d for client fd=%d", state, key->fd);
}

void stm_error_monitoring_arrival(unsigned state, struct selector_key *key) {
    log(ERROR, "Error in state %d for client fd=%d", state, key->fd);
    MonitoringClientData *MonitoringClientData = key->data;
    MonitoringClientData->connection_should_close = 1;
}

void stm_done_monitoring_arrival(unsigned state, struct selector_key *key) {
    log(INFO, "State %d completed for client fd=%d", state, key->fd);
    MonitoringClientData *MonitoringClientData = key->data;
    MonitoringClientData->connection_should_close = 1;
}

enum StateMonitoring stm_login_monitoring_read(struct selector_key *key) {
    MonitoringClientData *clientData = key->data;
    
    // 1. Leer datos al buffer (respetando toRead)
    ssize_t bytesRead = recv_to_monitoring_buffer(key->fd, &clientData->client_buffer, clientData->toRead);
    
    if (bytesRead <= 0) {
        if (bytesRead == 0) {
            log(INFO, "Client fd=%d closed connection during login", key->fd);
        } else {
            log(ERROR, "recv() failed in login_read for fd=%d: %s", key->fd, strerror(errno));
        }
        return STM_MONITORING_ERROR;
    }
    
    // 2. Actualizar contador
    clientData->toRead -= bytesRead;
    
    // 3. Verificar si tenemos datos suficientes
    if (clientData->toRead > 0) {
        return STM_LOGIN_MONITORING_READ; // Necesita más datos
    }
    
    // 4. Parsear login (ahora sabemos que tenemos todos los datos)
    if (clientData->parsing_state == 0) {
        // Primer byte: comando (debería ser LOGIN)
        uint8_t command = buffer_read(&clientData->client_buffer);
        if (command != 1) { // Asumiendo que LOGIN = 1
            log(ERROR, "Invalid login command %d from client fd=%d", command, key->fd);
            return STM_MONITORING_ERROR;
        }
        
        // Necesitamos leer longitud de username
        clientData->toRead = 1;
        clientData->parsing_state = 1;
        return STM_LOGIN_MONITORING_READ;
    }
    
    if (clientData->parsing_state == 1) {
        // Leer longitud de username
        uint8_t usernameLength = buffer_read(&clientData->client_buffer);
        if (usernameLength <= 0 || usernameLength >= 64) {
            log(ERROR, "Invalid username length %d from client fd=%d", usernameLength, key->fd);
            return STM_MONITORING_ERROR;
        }
        
        // Necesitamos username + 1 byte (password length)
        clientData->toRead = usernameLength + 1;
        clientData->parsing_state = 2;
        clientData->expected_message_size = usernameLength;
        return STM_LOGIN_MONITORING_READ;
    }
    
    if (clientData->parsing_state == 2) {
        // Leer username
        buffer_read_bytes(&clientData->client_buffer, (uint8_t*)clientData->username, clientData->expected_message_size);
        clientData->username[clientData->expected_message_size] = '\0';
        
        // Leer longitud de password
        uint8_t passwordLength = buffer_read(&clientData->client_buffer);
        if (passwordLength <= 0 || passwordLength >= 64) {
            log(ERROR, "Invalid password length %d from client fd=%d", passwordLength, key->fd);
            return STM_MONITORING_ERROR;
        }
        
        // Necesitamos el password
        clientData->toRead = passwordLength;
        clientData->parsing_state = 3;
        clientData->expected_message_size = passwordLength;
        return STM_LOGIN_MONITORING_READ;
    }
    
    if (clientData->parsing_state == 3) {
        // Leer password
        buffer_read_bytes(&clientData->client_buffer, (uint8_t*)clientData->password, clientData->expected_message_size);
        clientData->password[clientData->expected_message_size] = '\0';
        
        log(INFO, "Login attempt from client fd=%d, username: %s", key->fd, clientData->username);
        
        // Reset para próxima fase
        clientData->toRead = 1;
        clientData->parsing_state = 0;
        
        selector_set_interest_key(key, OP_WRITE);
        return STM_LOGIN_MONITORING_WRITE;
    }
    
    return STM_MONITORING_ERROR;
}

enum StateMonitoring stm_login_monitoring_write(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;

    if (validate_login(MonitoringClientData->username, MonitoringClientData->password)) {
        log(DEBUG, "Login successful for user: %s", MonitoringClientData->username);
        char message[2] = {1, 1};
        ssize_t sent = send(key->fd, message, 2, 0);
        
        if (sent < 0) {
            log(ERROR, "Failed to send login success response to client fd=%d: %s", key->fd, strerror(errno));
            return STM_MONITORING_ERROR;
        }

        selector_set_interest_key(key, OP_READ);
        return STM_REQUEST_MONITORING_READ;
    } else {
        log(DEBUG, "Login failed for user: %s", MonitoringClientData->username);
        char message[2] = {1, 0};
        ssize_t sent = send(key->fd, message, 2, 0);
        
        if (sent < 0) {
            log(ERROR, "Failed to send login failure response to client fd=%d: %s", key->fd, strerror(errno));
        }

        return STM_MONITORING_ERROR;
    }
}

enum StateMonitoring stm_request_monitoring_read(struct selector_key *key) {
    MonitoringClientData *clientData = key->data;
    
    // 1. Leer datos al buffer
    ssize_t bytesRead = recv_to_monitoring_buffer(key->fd, &clientData->client_buffer, clientData->toRead);
    
    if (bytesRead <= 0) {
        if (bytesRead == 0) {
            log(INFO, "Client fd=%d closed connection during request", key->fd);
        } else {
            log(ERROR, "recv() failed in request_read for fd=%d: %s", key->fd, strerror(errno));
        }
        return STM_MONITORING_ERROR;
    }
    
    // 2. Actualizar contador
    clientData->toRead -= bytesRead;
    
    // 3. Verificar si tenemos datos suficientes
    if (clientData->toRead > 0) {
        return STM_REQUEST_MONITORING_READ; // Necesita más datos
    }
    
    // 4. Parsear según estado
    if (clientData->parsing_state == 0) {
        // Leer comando
        uint8_t command = buffer_read(&clientData->client_buffer);
        
        // Determinar cuántos bytes más necesita según el comando
        switch(command) {
            case LIST_USERS:
            case GET_METRICS:
                // Comandos sin parámetros - ya terminamos
                clientData->buffer[0] = command;
                clientData->bytes = 1;
                clientData->toRead = 1; // Reset para próximo comando
                clientData->parsing_state = 0;
                selector_set_interest_key(key, OP_WRITE);
                return STM_REQUEST_MONITORING_WRITE;
                
            case ADD_USER:
            case CHANGE_PASSWORD:
                // Necesitamos leer longitud de username
                clientData->buffer[0] = command;
                clientData->toRead = 1;
                clientData->parsing_state = 1;
                clientData->bytes = 1; // Ya tenemos el comando
                return STM_REQUEST_MONITORING_READ;
                
            case REMOVE_USER:
                // Solo necesita username
                clientData->buffer[0] = command;
                clientData->toRead = 1;
                clientData->parsing_state = 4; // Estado especial para REMOVE
                clientData->bytes = 1;
                return STM_REQUEST_MONITORING_READ;
                
            default:
                clientData->buffer[0] = command;
                clientData->bytes = 1;
                clientData->toRead = 1;
                clientData->parsing_state = 0;
                selector_set_interest_key(key, OP_WRITE);
                return STM_REQUEST_MONITORING_WRITE;
        }
    }
    
    // Estados para ADD_USER y CHANGE_PASSWORD
    if (clientData->parsing_state == 1) {
        // Leer longitud de username
        uint8_t usernameLength = buffer_read(&clientData->client_buffer);
        clientData->buffer[clientData->bytes++] = usernameLength;
        
        clientData->toRead = usernameLength;
        clientData->parsing_state = 2;
        clientData->expected_message_size = usernameLength;
        return STM_REQUEST_MONITORING_READ;
    }
    
    if (clientData->parsing_state == 2) {
        // Leer username
        buffer_read_bytes(&clientData->client_buffer, (uint8_t*)&clientData->buffer[clientData->bytes], clientData->expected_message_size);
        clientData->bytes += clientData->expected_message_size;
        
        // Para CHANGE_PASSWORD necesitamos password, para ADD_USER también
        clientData->toRead = 1; // Longitud de password
        clientData->parsing_state = 3;
        return STM_REQUEST_MONITORING_READ;
    }
    
    if (clientData->parsing_state == 3) {
        // Leer longitud de password
        uint8_t passwordLength = buffer_read(&clientData->client_buffer);
        clientData->buffer[clientData->bytes++] = passwordLength;
        
        clientData->toRead = passwordLength;
        clientData->parsing_state = 5; // Estado final
        clientData->expected_message_size = passwordLength;
        return STM_REQUEST_MONITORING_READ;
    }
    
    if (clientData->parsing_state == 4) {
        // Estado especial para REMOVE_USER (solo username)
        uint8_t usernameLength = buffer_read(&clientData->client_buffer);
        clientData->buffer[clientData->bytes++] = usernameLength;
        
        clientData->toRead = usernameLength;
        clientData->parsing_state = 6; // Estado final para REMOVE
        clientData->expected_message_size = usernameLength;
        return STM_REQUEST_MONITORING_READ;
    }
    
    if (clientData->parsing_state == 5) {
        // Leer password (estado final para ADD_USER/CHANGE_PASSWORD)
        buffer_read_bytes(&clientData->client_buffer, (uint8_t*)&clientData->buffer[clientData->bytes], clientData->expected_message_size);
        clientData->bytes += clientData->expected_message_size;
        
        // Reset para próximo comando
        clientData->toRead = 1;
        clientData->parsing_state = 0;
        
        selector_set_interest_key(key, OP_WRITE);
        return STM_REQUEST_MONITORING_WRITE;
    }
    
    if (clientData->parsing_state == 6) {
        // Leer username (estado final para REMOVE_USER)
        buffer_read_bytes(&clientData->client_buffer, (uint8_t*)&clientData->buffer[clientData->bytes], clientData->expected_message_size);
        clientData->bytes += clientData->expected_message_size;
        
        // Reset para próximo comando
        clientData->toRead = 1;
        clientData->parsing_state = 0;
        
        selector_set_interest_key(key, OP_WRITE);
        return STM_REQUEST_MONITORING_WRITE;
    }
    
    return STM_MONITORING_ERROR;
}

enum StateMonitoring stm_request_monitoring_write(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    
    if (MonitoringClientData->bytes <= 0) {
        log(ERROR, "No data to process in request_write for fd=%d", key->fd);
        return STM_MONITORING_ERROR;
    }
    
    char command = MonitoringClientData->buffer[0];
    char *buffer = MonitoringClientData->buffer;
    
    log(DEBUG, "Processing command %d for client fd=%d", command, key->fd);
    
    char response[RESPONSE_BUFFER_SIZE];
    int result = 0;
    
    switch(command) {
        case LIST_USERS:
            result = handle_list_users_command(response, sizeof(response));
            break;
            
        case ADD_USER:
            result = handle_add_user_command(buffer, MonitoringClientData->bytes, response, sizeof(response));
            break;
            
        case REMOVE_USER:
            result = handle_remove_user_command(buffer, MonitoringClientData->bytes, response, sizeof(response));
            break;
            
        case CHANGE_PASSWORD:
            result = handle_change_password_command(buffer, MonitoringClientData->bytes, response, sizeof(response));
            break;

        case GET_METRICS:
            result = handle_get_metrics_command(response, sizeof(response));
            break;
            
        default:
            result = handle_unknown_command(command, response, sizeof(response));
            break;
    }
    
    if (result < 0) {
        log(ERROR, "Command processing failed for command %d", command);
        return STM_MONITORING_ERROR;
    }
    
    ssize_t sent = send(key->fd, response, strlen(response), 0);
    if (sent < 0) {
        log(ERROR, "Failed to send response to client fd=%d: %s", key->fd, strerror(errno));
        return STM_MONITORING_ERROR;
    }
    
    log(DEBUG, "Sent %zd bytes response to client fd=%d", sent, key->fd);
    return STM_MONITORING_DONE;
}

static const struct state_definition CLIENT_STATE_MONITORING_TABLE[] = {
    {
        .state = STM_LOGIN_MONITORING_READ,
        .on_arrival = stm_read_monitoring_arrival,
        .on_read_ready = stm_login_monitoring_read,
    },
    {
        .state = STM_LOGIN_MONITORING_WRITE,
        .on_write_ready = stm_login_monitoring_write,
    },
    {
        .state = STM_REQUEST_MONITORING_READ,
        .on_arrival = stm_read_monitoring_arrival,
        .on_read_ready = stm_request_monitoring_read,
    },
    {
        .state = STM_REQUEST_MONITORING_WRITE,
        .on_write_ready = stm_request_monitoring_write,
    },
    {
        .state = STM_MONITORING_DONE,
        .on_arrival = stm_done_monitoring_arrival,
    },
    {
        .state = STM_MONITORING_ERROR,
        .on_arrival = stm_error_monitoring_arrival,
    },
};

void client_handler_monitoring_read(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    enum StateMonitoring state = stm_handler_read(&MonitoringClientData->stm, key);
    
    if (state == STM_MONITORING_ERROR || MonitoringClientData->connection_should_close) {
        log(DEBUG, "Closing connection for client fd=%d (state=%d, should_close=%d)", 
            key->fd, state, MonitoringClientData->connection_should_close);
        selector_unregister_fd(key->s, key->fd);
        return;
    }
}

void client_handler_monitoring_write(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    enum StateMonitoring state = stm_handler_write(&MonitoringClientData->stm, key);
    
    if (state == STM_MONITORING_ERROR || MonitoringClientData->connection_should_close) {
        log(DEBUG, "Closing connection for client fd=%d (state=%d, should_close=%d)", 
            key->fd, state, MonitoringClientData->connection_should_close);
        selector_unregister_fd(key->s, key->fd);
        return;
    }
}

void client_handler_monitoring_block(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    enum StateMonitoring state = stm_handler_block(&MonitoringClientData->stm, key);
    
    if (state == STM_MONITORING_ERROR || MonitoringClientData->connection_should_close) {
        log(DEBUG, "Closing connection for client fd=%d (state=%d, should_close=%d)", 
            key->fd, state, MonitoringClientData->connection_should_close);
        selector_unregister_fd(key->s, key->fd);
        return;
    }
}

void client_handler_monitoring_close(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    log(INFO, "Closing connection for client fd=%d", key->fd);
    
    close(key->fd);
    
    if (MonitoringClientData) {
        free(MonitoringClientData);
    }
}

void handle_read_passive_monitoring(struct selector_key *key) {
    int clientSocket = acceptTCPConnection(key->fd);
    if (clientSocket < 0) {
        return;
    }

    if (selector_fd_set_nio(clientSocket) < 0) {
        log(ERROR, "Could not set O_NONBLOCK on client socket fd=%d", clientSocket);
        close(clientSocket);
        return;
    }

    fd_handler *clientHandler = malloc(sizeof(fd_handler));
    if (!clientHandler) {
        log(ERROR, "Failed to allocate memory for client handler");
        close(clientSocket);
        return;
    }

    clientHandler->handle_read = client_handler_monitoring_read;
    clientHandler->handle_write = client_handler_monitoring_write;
    clientHandler->handle_close = client_handler_monitoring_close;
    clientHandler->handle_block = client_handler_monitoring_block;

    log(DEBUG, "Size of MonitoringClientData: %zu bytes", sizeof(struct MonitoringClientData));
    log(DEBUG, "Size of buffer field: %zu bytes", sizeof(((MonitoringClientData*)0)->buffer));
    MonitoringClientData *MonitoringClientData = calloc(1, sizeof(struct MonitoringClientData));
    if (!MonitoringClientData) {
        log(ERROR, "Failed to allocate memory for client data");
        free(clientHandler);
        close(clientSocket);
        return;
    }
    log(DEBUG, "Allocated %zu bytes for MonitoringClientData", sizeof(struct MonitoringClientData));

    
    buffer_init(&MonitoringClientData->client_buffer, BUFSIZE_MONITORING, MonitoringClientData->buffer_data);
    MonitoringClientData->toRead = 1;
    MonitoringClientData->parsing_state = 0;
    MonitoringClientData->expected_message_size = 0;

    MonitoringClientData->stm.initial = STM_LOGIN_MONITORING_READ;
    MonitoringClientData->stm.max_state = STM_MONITORING_ERROR;
    MonitoringClientData->stm.states = CLIENT_STATE_MONITORING_TABLE;
    MonitoringClientData->connection_should_close = 0;

    stm_init(&MonitoringClientData->stm);

    if (selector_register(key->s, clientSocket, clientHandler, OP_READ, (void *)MonitoringClientData) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to register client socket fd=%d in selector", clientSocket);
        free(clientHandler);
        free(MonitoringClientData);
        close(clientSocket);
        return;
    }

    log(DEBUG, "Client fd=%d registered successfully in selector", clientSocket);
}