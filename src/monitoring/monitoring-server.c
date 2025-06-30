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
    MonitoringClientData *MonitoringClientData = key->data;
    memset(MonitoringClientData->buffer, 0, BUFSIZE_MONITORING);
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
    MonitoringClientData *MonitoringClientData = key->data;
    ssize_t bytes = recv(key->fd, MonitoringClientData->buffer, BUFSIZE_MONITORING - 1, 0);
    
    if (bytes <= 0) {
        log(ERROR, "Failed to receive login data from client fd=%d", key->fd);
        return STM_MONITORING_ERROR;
    }
    
    char *message = MonitoringClientData->buffer;
    if (bytes < 3) {
        log(ERROR, "Invalid login message length %zd from client fd=%d", bytes, key->fd);
        return STM_MONITORING_ERROR;
    }

    int index = 1;
    int usernameLength = (unsigned char)message[index++];
    
    if (usernameLength <= 0 || usernameLength >= 64 || index + usernameLength >= bytes) {
        log(ERROR, "Invalid username length %d from client fd=%d", usernameLength, key->fd);
        return STM_MONITORING_ERROR;
    }

    memcpy(MonitoringClientData->username, message + index, usernameLength);
    MonitoringClientData->username[usernameLength] = '\0';
    index += usernameLength;
    
    if (index >= bytes) {
        log(ERROR, "Invalid message format from client fd=%d", key->fd);
        return STM_MONITORING_ERROR;
    }
    
    int passwordLength = (unsigned char)message[index++];
    
    if (passwordLength <= 0 || passwordLength >= 64 || index + passwordLength > bytes) {
        log(ERROR, "Invalid password length %d from client fd=%d", passwordLength, key->fd);
        return STM_MONITORING_ERROR;
    }

    memcpy(MonitoringClientData->password, message + index, passwordLength);
    MonitoringClientData->password[passwordLength] = '\0';
    log(INFO, "Login attempt from client fd=%d, username: %s", key->fd, MonitoringClientData->username);

    selector_set_interest_key(key, OP_WRITE);
    return STM_LOGIN_MONITORING_WRITE;
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
    MonitoringClientData *MonitoringClientData = key->data;
    ssize_t bytes = recv(key->fd, MonitoringClientData->buffer, BUFSIZE_MONITORING - 1, 0);
    
    if (bytes <= 0) {
        if (bytes == 0) {
            log(INFO, "Client fd=%d closed connection during request", key->fd);
        } else {
            log(ERROR, "recv() failed in request_read for fd=%d: %s", key->fd, strerror(errno));
        }
        return STM_MONITORING_ERROR;
    }

    log(DEBUG, "Received %zd bytes for request from client fd=%d", bytes, key->fd);
    print_hex_compact("Request data received", (unsigned char*)MonitoringClientData->buffer, bytes);

    MonitoringClientData->bytes = bytes;
    selector_set_interest_key(key, OP_WRITE);
    return STM_REQUEST_MONITORING_WRITE;
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
    log(DEBUG, "Allocated %zu bytes for MonitoringClientData", sizeof(MonitoringClientData));

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