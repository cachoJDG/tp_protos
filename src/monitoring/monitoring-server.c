#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include "../shared/logger.h"
#include "../shared/util.h"
#include <signal.h>
#include "../users/users.h"
#include <stdlib.h>
#include "monitoring-server.h"
#include "monitoringServerUtils.h"

struct sockaddr_storage _localAddr;

// Helper function for debugging, as buffer_readable_bytes is not in buffer.h
static size_t get_buffer_readable_bytes(buffer *b) {
    size_t nbyte;
    buffer_read_ptr(b, &nbyte);
    return nbyte;
}

int acceptTCPConnection(int servSock) {
	struct sockaddr_storage clntAddr;
	socklen_t clntAddrLen = sizeof(clntAddr);
    static char addrBuffer[MAX_ADDR_BUFFER];

	// Wait for a client to connect
	int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
	if (clntSock < 0) {
		return -1;
	}
    if(selector_fd_set_nio(clntSock) < 0) {
        return -1;
    }

	printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);
	log(INFO, "Handling client %s", addrBuffer);

	return clntSock;
}

uint32_t getBytesToReadFromTwoBytes(char *buffer) {
    uint32_t bytesToRead;
    memcpy(&bytesToRead, buffer, 2);
    return ntohs(bytesToRead) + 2;
}
    

ssize_t recv_to_monitoring_buffer(int fd, buffer *buf, ssize_t maxBytes) {
    ssize_t available = 0;
    uint8_t *writePtr = buffer_write_ptr(buf, (size_t *)&available);
    
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

void stm_read_monitoring_arrival(unsigned state, struct selector_key *key) {
    MonitoringClientData *clientData = key->data;
    
    // In case of a new connection or state transition, reset the buffer
    buffer_reset(&clientData->client_buffer);
    clientData->expected_message_size = 0; // Reset expected message size

    if (state == STM_LOGIN_MONITORING_READ) {
        clientData->toRead = 1; // Expecting version byte first
        clientData->parsing_state = LOGIN_PARSE_VERSION_AND_UNAME_LEN; // Initial parsing state for login
    } else if (state == STM_REQUEST_MONITORING_READ) {
        clientData->toRead = 1; // Expecting command byte first
        clientData->parsing_state = REQUEST_PARSE_COMMAND_TYPE; // Initial parsing state for requests
    }
    
    log(DEBUG, "Entering state %d for client fd=%d, parsing_state=%d, toRead=%zd", state, key->fd, clientData->parsing_state, clientData->toRead);
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
    
    // 1. Leer datos al buffer
    ssize_t bytesRead = recv_to_monitoring_buffer(key->fd, &clientData->client_buffer, clientData->toRead);
    
    if (bytesRead <= 0) {
        if (bytesRead == 0) {
            log(INFO, "Client fd=%d closed connection during login", key->fd);
        } else {
            log(ERROR, "recv() failed in login_read for fd=%d: %s", key->fd, strerror(errno));
        }
        return STM_MONITORING_ERROR;
    }
    
    
    clientData->toRead -= bytesRead;
    
    
    if (clientData->toRead > 0) {
        log(DEBUG, "Still need %zd bytes for parsing_state %d for client fd=%d", clientData->toRead, clientData->parsing_state, key->fd);
        return STM_LOGIN_MONITORING_READ; // Necesita más datos para el paso actual
    }
    
    
    if (clientData->parsing_state == LOGIN_PARSE_VERSION_AND_UNAME_LEN) {
        uint8_t command = buffer_read(&clientData->client_buffer);
        log(DEBUG, "Parsed login command: %d. Readable bytes left: %zu", command, get_buffer_readable_bytes(&clientData->client_buffer));
        if (command != 1) {
            log(ERROR, "Invalid login command %d from client fd=%d", command, key->fd);
            return STM_MONITORING_ERROR;
        }
        clientData->toRead = 1;
        clientData->parsing_state = LOGIN_PARSE_UNAME_AND_PASS_LEN;
        return STM_LOGIN_MONITORING_READ;
    }
    
    if (clientData->parsing_state == LOGIN_PARSE_UNAME_AND_PASS_LEN) {
        uint8_t usernameLength = buffer_read(&clientData->client_buffer);
        log(DEBUG, "Parsed username length: %d. Readable bytes left: %zu", usernameLength, get_buffer_readable_bytes(&clientData->client_buffer));
        if (usernameLength <= 0 || usernameLength >= UNAME_MAX_LENGTH) {
            log(ERROR, "Invalid username length %d from client fd=%d", usernameLength, key->fd);
            return STM_MONITORING_ERROR;
        }
        clientData->expected_message_size = usernameLength;
        clientData->toRead = usernameLength + 1;
        clientData->parsing_state = LOGIN_PARSE_PASSWORD_BYTES;
        return STM_LOGIN_MONITORING_READ;
    }
    
    if (clientData->parsing_state == LOGIN_PARSE_PASSWORD_BYTES) {

        log(DEBUG, "Reading username. Expected size: %zu. Readable bytes in buffer: %zu", clientData->expected_message_size, get_buffer_readable_bytes(&clientData->client_buffer));

        if (!buffer_read_bytes(&clientData->client_buffer, (uint8_t*)clientData->username, clientData->expected_message_size)) {
            log(ERROR, "Failed to read username bytes for client fd=%d", key->fd);
            return STM_MONITORING_ERROR;
        }
        clientData->username[clientData->expected_message_size] = '\0';
        log(DEBUG, "Parsed username: %s. Readable bytes left: %zu", clientData->username, get_buffer_readable_bytes(&clientData->client_buffer));

        uint8_t passwordLength = buffer_read(&clientData->client_buffer); // Consumes 1 byte
        log(DEBUG, "Parsed password length: %d. Readable bytes left: %zu", passwordLength, get_buffer_readable_bytes(&clientData->client_buffer));
        if (passwordLength <= 0 || passwordLength >= PASSWORD_MAX_LENGTH) {
            log(ERROR, "Invalid password length %d from client fd=%d", passwordLength, key->fd);
            return STM_MONITORING_ERROR;
        }
        clientData->expected_message_size = passwordLength;
        clientData->toRead = passwordLength;
        clientData->parsing_state = LOGIN_PARSE_DONE;
        return STM_LOGIN_MONITORING_READ;
    }
    
    if (clientData->parsing_state == LOGIN_PARSE_DONE) {

        log(DEBUG, "Reading password. Expected size: %zu. Readable bytes in buffer: %zu", clientData->expected_message_size, get_buffer_readable_bytes(&clientData->client_buffer));

        if (!buffer_read_bytes(&clientData->client_buffer, (uint8_t*)clientData->password, clientData->expected_message_size)) {
            log(ERROR, "Failed to read password bytes for client fd=%d", key->fd);
            return STM_MONITORING_ERROR;
        }
        clientData->password[clientData->expected_message_size] = '\0';
        
        log(INFO, "Login attempt from client fd=%d, username: %s", key->fd, clientData->username);
        

        clientData->toRead = 1;
        clientData->parsing_state = REQUEST_PARSE_COMMAND_TYPE;
        
        selector_set_interest_key(key, OP_WRITE);
        return STM_LOGIN_MONITORING_WRITE;
    }
    
    log(ERROR, "Reached unexpected parsing state %d for client fd=%d", clientData->parsing_state, key->fd);
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
    
    // 1. Leer datos al buffer (respetando toRead)
    ssize_t bytesRead = recv_to_monitoring_buffer(key->fd, &clientData->client_buffer, clientData->toRead);
    
    if (bytesRead <= 0) {
        if (bytesRead == 0) {
            log(INFO, "Client fd=%d closed connection during request", key->fd);
        } else {
            log(ERROR, "recv() failed in request_read for fd=%d: %s", key->fd, strerror(errno));
        }
        return STM_MONITORING_ERROR;
    }
    
    // 2. Actualizar contador de bytes pendientes para el paso actual
    clientData->toRead -= bytesRead;
    
    // 3. Verificar si tenemos datos suficientes para el *paso actual*
    if (clientData->toRead > 0) {
        log(DEBUG, "Still need %zd bytes for parsing_state %d for client fd=%d", clientData->toRead, clientData->parsing_state, key->fd);
        return STM_REQUEST_MONITORING_READ; // Necesita más datos para el paso actual
    }
    
    // 4. Si toRead es 0, significa que los bytes para el paso actual llegaron.
    //    Ahora, procesamos esos bytes y avanzamos el sub-estado de parsing.
    
    if (clientData->parsing_state == REQUEST_PARSE_COMMAND_TYPE) {
        uint8_t command = buffer_read(&clientData->client_buffer);
        clientData->buffer[0] = command;
        clientData->bytes = 1;
        log(DEBUG, "Parsed request command: %d. Readable bytes left: %zu", command, get_buffer_readable_bytes(&clientData->client_buffer));

        switch(command) {
            case LIST_USERS:
            case GET_METRICS:
                clientData->toRead = 0;
                clientData->parsing_state = REQUEST_PARSE_DONE;
                break;
                
            case ADD_USER:
            case CHANGE_PASSWORD:
                clientData->toRead = 1;
                clientData->parsing_state = REQUEST_PARSE_ADD_CHANGE_UNAME_LEN;
                break;
                
            case REMOVE_USER:
                clientData->toRead = 1;
                clientData->parsing_state = REQUEST_PARSE_REMOVE_UNAME_LEN;
                break;

            case CHANGE_ROLE:
                clientData->toRead = 1;
                clientData->parsing_state = REQUEST_PARSE_CHANGE_ROLE_UNAME_LEN;
                break;
                
            default:
                clientData->toRead = 0;
                clientData->parsing_state = REQUEST_PARSE_DONE;
                break;
        }
        // Si el comando es LIST_USERS o GET_METRICS, o desconocido, ya está listo para escribir.
        if (clientData->parsing_state == REQUEST_PARSE_DONE) {
            selector_set_interest_key(key, OP_WRITE);
            return STM_REQUEST_MONITORING_WRITE;
        }
        return STM_REQUEST_MONITORING_READ; // Regresar para esperar los siguientes bytes
    }
    
    // Estados para ADD_USER y CHANGE_PASSWORD
    if (clientData->parsing_state == REQUEST_PARSE_ADD_CHANGE_UNAME_LEN) {
        uint8_t usernameLength = buffer_read(&clientData->client_buffer);
        clientData->buffer[clientData->bytes++] = usernameLength;
        log(DEBUG, "Parsed username length for ADD/CHANGE: %d. Readable bytes left: %zu", usernameLength, get_buffer_readable_bytes(&clientData->client_buffer));
        
        clientData->toRead = usernameLength;
        clientData->parsing_state = REQUEST_PARSE_ADD_CHANGE_UNAME;
        clientData->expected_message_size = usernameLength;
        return STM_REQUEST_MONITORING_READ;
    }
    
    if (clientData->parsing_state == REQUEST_PARSE_ADD_CHANGE_UNAME) {
        log(DEBUG, "Reading username bytes for ADD/CHANGE. Expected size: %zu. Readable bytes: %zu", clientData->expected_message_size, get_buffer_readable_bytes(&clientData->client_buffer));
        if (!buffer_read_bytes(&clientData->client_buffer, (uint8_t*)&clientData->buffer[clientData->bytes], clientData->expected_message_size)) {
            log(ERROR, "Failed to read username bytes for ADD/CHANGE for client fd=%d", key->fd);
            return STM_MONITORING_ERROR;
        }
        clientData->bytes += clientData->expected_message_size;
        log(DEBUG, "Username bytes read for ADD/CHANGE. Readable bytes left: %zu", get_buffer_readable_bytes(&clientData->client_buffer));
        
        clientData->toRead = 1;
        clientData->parsing_state = REQUEST_PARSE_ADD_CHANGE_PASS_LEN;
        return STM_REQUEST_MONITORING_READ;
    }
    
    if (clientData->parsing_state == REQUEST_PARSE_ADD_CHANGE_PASS_LEN) {
        uint8_t passwordLength = buffer_read(&clientData->client_buffer);
        clientData->buffer[clientData->bytes++] = passwordLength;
        log(DEBUG, "Parsed password length for ADD/CHANGE: %d. Readable bytes left: %zu", passwordLength, get_buffer_readable_bytes(&clientData->client_buffer));
        
        clientData->toRead = passwordLength;
        clientData->parsing_state = REQUEST_PARSE_ADD_CHANGE_PASS;
        clientData->expected_message_size = passwordLength;
        return STM_REQUEST_MONITORING_READ;
    }
    
    if (clientData->parsing_state == REQUEST_PARSE_REMOVE_UNAME_LEN) {
        uint8_t usernameLength = buffer_read(&clientData->client_buffer);
        clientData->buffer[clientData->bytes++] = usernameLength;
        log(DEBUG, "Parsed username length for REMOVE: %d. Readable bytes left: %zu", usernameLength, get_buffer_readable_bytes(&clientData->client_buffer));
        
        clientData->toRead = usernameLength;
        clientData->parsing_state = REQUEST_PARSE_REMOVE_UNAME;
        clientData->expected_message_size = usernameLength;
        return STM_REQUEST_MONITORING_READ;
    }
    
    if (clientData->parsing_state == REQUEST_PARSE_ADD_CHANGE_PASS) {
        log(DEBUG, "Reading password bytes for ADD/CHANGE. Expected size: %zu. Readable bytes: %zu", clientData->expected_message_size, get_buffer_readable_bytes(&clientData->client_buffer));
        if (!buffer_read_bytes(&clientData->client_buffer, (uint8_t*)&clientData->buffer[clientData->bytes], clientData->expected_message_size)) {
            log(ERROR, "Failed to read password bytes for ADD/CHANGE for client fd=%d", key->fd);
            return STM_MONITORING_ERROR;
        }
        clientData->bytes += clientData->expected_message_size;
        log(DEBUG, "Password bytes read for ADD/CHANGE. Readable bytes left: %zu", get_buffer_readable_bytes(&clientData->client_buffer));
        
        clientData->toRead = 0;
        clientData->parsing_state = REQUEST_PARSE_DONE;
        selector_set_interest_key(key, OP_WRITE);
        return STM_REQUEST_MONITORING_WRITE;
    }
    
    if (clientData->parsing_state == REQUEST_PARSE_REMOVE_UNAME) {
        log(DEBUG, "Reading username bytes for REMOVE. Expected size: %zu. Readable bytes: %zu", clientData->expected_message_size, get_buffer_readable_bytes(&clientData->client_buffer));
        if (!buffer_read_bytes(&clientData->client_buffer, (uint8_t*)&clientData->buffer[clientData->bytes], clientData->expected_message_size)) {
            log(ERROR, "Failed to read username bytes for REMOVE for client fd=%d", key->fd);
            return STM_MONITORING_ERROR;
        }
        clientData->bytes += clientData->expected_message_size;
        log(DEBUG, "Username bytes read for REMOVE. Readable bytes left: %zu", get_buffer_readable_bytes(&clientData->client_buffer));
        
        clientData->toRead = 0;
        clientData->parsing_state = REQUEST_PARSE_DONE;
        selector_set_interest_key(key, OP_WRITE);
        return STM_REQUEST_MONITORING_WRITE;
    }

    if (clientData->parsing_state == REQUEST_PARSE_CHANGE_ROLE_UNAME_LEN) {
        uint8_t usernameLength = buffer_read(&clientData->client_buffer);
        clientData->buffer[clientData->bytes++] = usernameLength;
        log(DEBUG, "Parsed username length for CHANGE_ROLE: %d. Readable bytes left: %zu", usernameLength, get_buffer_readable_bytes(&clientData->client_buffer));
        
        clientData->toRead = usernameLength + 1;
        clientData->parsing_state = REQUEST_PARSE_CHANGE_ROLE_UNAME_AND_ROLE;
        clientData->expected_message_size = usernameLength;
        return STM_REQUEST_MONITORING_READ;
    }

    if (clientData->parsing_state == REQUEST_PARSE_CHANGE_ROLE_UNAME_AND_ROLE) {
        log(DEBUG, "Reading username and role bytes for CHANGE_ROLE. Expected username size: %zu. Readable bytes: %zu", clientData->expected_message_size, get_buffer_readable_bytes(&clientData->client_buffer));
        if (!buffer_read_bytes(&clientData->client_buffer, (uint8_t*)&clientData->buffer[clientData->bytes], clientData->expected_message_size)) {
            log(ERROR, "Failed to read username bytes for CHANGE_ROLE for client fd=%d", key->fd);
            return STM_MONITORING_ERROR;
        }
        clientData->bytes += clientData->expected_message_size;
        
        uint8_t role = buffer_read(&clientData->client_buffer);
        clientData->buffer[clientData->bytes++] = role;
        log(DEBUG, "Parsed role for CHANGE_ROLE: %d. Readable bytes left: %zu", role, get_buffer_readable_bytes(&clientData->client_buffer));
        
        clientData->toRead = 0;
        clientData->parsing_state = REQUEST_PARSE_DONE;
        selector_set_interest_key(key, OP_WRITE);
        return STM_REQUEST_MONITORING_WRITE;
    }
    
    if (clientData->parsing_state == REQUEST_PARSE_DONE) {
        clientData->toRead = 1;
        clientData->parsing_state = REQUEST_PARSE_COMMAND_TYPE;
        selector_set_interest_key(key, OP_WRITE);
        return STM_REQUEST_MONITORING_WRITE;
    }

    log(ERROR, "Reached unexpected parsing state %d for client fd=%d", clientData->parsing_state, key->fd);
    return STM_MONITORING_ERROR;
}

enum StateMonitoring stm_request_monitoring_write(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    
    if (MonitoringClientData->bytes <= 0) {
        log(ERROR, "No data to process in request_write for fd=%d", key->fd);
        return STM_MONITORING_ERROR;
    }
    
    char command = MonitoringClientData->buffer[0];
    uint8_t *buffer = MonitoringClientData->buffer;
    
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
            result = handle_remove_user_command(buffer, MonitoringClientData->bytes, response, sizeof(response), MonitoringClientData->username);
            break;
            
        case CHANGE_PASSWORD:
            result = handle_change_password_command(buffer, MonitoringClientData->bytes, response, sizeof(response), MonitoringClientData->username);
            break;

        case GET_METRICS:
            result = handle_get_metrics_command(response, sizeof(response));
            break;

        case CHANGE_ROLE:
            result = handle_change_role_command(buffer, MonitoringClientData->bytes, response, sizeof(response), MonitoringClientData->username);
            break;
            
        default:
            result = handle_unknown_command(command, response, sizeof(response));
            break;
    }

    u_int32_t response_length = getBytesToReadFromTwoBytes(response); //se obtiene la longitud de la respuesta a partir de los primeros 2 bytes
    if(response_length > RESPONSE_BUFFER_SIZE) {
        log(ERROR, "Response size exceeds buffer limit for command %d", command);
        return STM_MONITORING_ERROR;
    }

    if (result < 0) {
        send(key->fd, response, response_length, 0);
        log(ERROR, "Command processing failed for command %d", command);
        return STM_MONITORING_ERROR;
    }
    
    ssize_t sent = send(key->fd, response, response_length, 0);
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

    MonitoringClientData *data = calloc(1, sizeof(*data));
    if (!data) {
        close(clientSocket);
        return;
    }

    buffer_init(&data->client_buffer, BUFSIZE_MONITORING, data->buffer_data);
    data->toRead               = 1;
    data->parsing_state        = LOGIN_PARSE_VERSION_AND_UNAME_LEN;
    data->expected_message_size= 0;
    data->stm.initial          = STM_LOGIN_MONITORING_READ;
    data->stm.max_state        = STM_MONITORING_ERROR;
    data->stm.states           = CLIENT_STATE_MONITORING_TABLE;
    data->connection_should_close = 0;
    stm_init(&data->stm);

    data->handler.handle_read  = client_handler_monitoring_read;
    data->handler.handle_write = client_handler_monitoring_write;
    data->handler.handle_block = client_handler_monitoring_block;
    data->handler.handle_close = client_handler_monitoring_close;

    log(DEBUG, "Size of MonitoringClientData: %zu bytes", sizeof(*data));
    log(DEBUG, "Size of buffer_data field: %zu bytes", sizeof(data->buffer));

    if (selector_register(key->s,
                          clientSocket,
                          &data->handler,
                          OP_READ,
                          data) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to register client socket fd=%d in selector", clientSocket);
        free(data);
        close(clientSocket);
        return;
    }

    log(DEBUG, "Client fd=%d registered successfully in selector", clientSocket);
}
