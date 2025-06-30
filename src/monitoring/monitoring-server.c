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

#define MAXPENDING 5
#define BUFSIZE_MONITORING 512
#define MAX_ADDR_BUFFER_MONITORING 128
#define SELECTOR_CAPACITY 256

static char addrBuffer[MAX_ADDR_BUFFER_MONITORING];
struct sockaddr_storage _localAddr;

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

int setupTCPServerSocket(const char *service) {
    struct addrinfo addrCriteria;
    memset(&addrCriteria, 0, sizeof(addrCriteria));
    addrCriteria.ai_family = AF_UNSPEC;
    addrCriteria.ai_flags = AI_PASSIVE;
    addrCriteria.ai_socktype = SOCK_STREAM;
    addrCriteria.ai_protocol = IPPROTO_TCP;

    struct addrinfo *servAddr;
    int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr);
    if (rtnVal != 0) {
        log(FATAL, "getaddrinfo() failed %s", gai_strerror(rtnVal));
        return -1;
    }

    int servSock = -1;
    for (struct addrinfo *addr = servAddr; addr != NULL && servSock == -1; addr = addr->ai_next) {
        errno = 0;
        servSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (servSock < 0) {
            log(DEBUG, "Can't create socket on %s : %s ", printAddressPort(addr, addrBuffer), strerror(errno));
            continue;
        }

        int opt = 1;
        if (setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            log(DEBUG, "setsockopt SO_REUSEADDR failed: %s", strerror(errno));
        }

        if ((bind(servSock, addr->ai_addr, addr->ai_addrlen) == 0) && (listen(servSock, MAXPENDING) == 0)) {
            struct sockaddr_storage localAddr;
            socklen_t addrSize = sizeof(localAddr);
            if (getsockname(servSock, (struct sockaddr *) &localAddr, &addrSize) >= 0) {
                printSocketAddress((struct sockaddr *) &localAddr, addrBuffer);
                _localAddr = localAddr;
                log(INFO, "Binding to %s", addrBuffer);
            }
        } else {
            log(DEBUG, "Can't bind %s", strerror(errno));
            close(servSock);
            servSock = -1;
        }
    }

    freeaddrinfo(servAddr);
    return servSock;
}

int acceptTCPConnection(int servSock) {
    struct sockaddr_storage clntAddr;
    socklen_t clntAddrLen = sizeof(clntAddr);

    int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
    if (clntSock < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log(ERROR, "accept() failed: %s", strerror(errno));
        }
        return -1;
    }

    printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);
    log(INFO, "Handling client %s", addrBuffer);

    return clntSock;
}

void stm_read_arrival(unsigned state, struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    memset(MonitoringClientData->buffer, 0, BUFSIZE_MONITORING);
    log(DEBUG, "Entering state %d for client fd=%d", state, key->fd);
}

void stm_error_arrival(unsigned state, struct selector_key *key) {
    log(ERROR, "Error in state %d for client fd=%d", state, key->fd);
    MonitoringClientData *MonitoringClientData = key->data;
    MonitoringClientData->connection_should_close = 1;
}

void stm_done_arrival(unsigned state, struct selector_key *key) {
    log(INFO, "State %d completed for client fd=%d", state, key->fd);
    MonitoringClientData *MonitoringClientData = key->data;
    MonitoringClientData->connection_should_close = 1;
}

enum StateMonitoring stm_login_read(struct selector_key *key) {
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

enum StateMonitoring stm_login_write(struct selector_key *key) {
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

enum StateMonitoring stm_request_read(struct selector_key *key) {
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

char *getStringFromSize(char *buffer) {
    if (!buffer) return NULL;
    
    unsigned char size = (unsigned char)buffer[0];
    if (size == 0) return NULL;
    
    char *str = malloc(size + 1);
    if (str == NULL) {
        log(ERROR, "malloc failed in getStringFromSize");
        return NULL;
    }
    
    memcpy(str, buffer + 1, size);
    str[size] = '\0';
    
    log(DEBUG, "Parsed string: %s (length: %d)", str, size);
    return str;
}

enum StateMonitoring stm_request_write(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    
    if (MonitoringClientData->bytes <= 0) {
        log(ERROR, "No data to process in request_write for fd=%d", key->fd);
        return STM_MONITORING_ERROR;
    }
    
    char command = MonitoringClientData->buffer[0];
    char *buffer = MonitoringClientData->buffer;
    
    log(DEBUG, "Processing command %d for client fd=%d", command, key->fd);
    
    char response[1024];
    switch(command) {
        case LIST_USERS:
            log(DEBUG, "Comando LIST_USERS recibido");
            snprintf(response, sizeof(response), "%s", getUsers());
            break;
            
        case ADD_USER: {
            log(DEBUG, "Comando ADD_USER recibido");
            
            if (MonitoringClientData->bytes < 4) {
                log(ERROR, "Invalid ADD_USER message length");
                snprintf(response, sizeof(response), "Error: Invalid message format\n");
                break;
            }
            
            char *usernameToAdd = getStringFromSize(buffer + 1);
            if (!usernameToAdd) {
                log(ERROR, "Failed to parse username in ADD_USER");
                snprintf(response, sizeof(response), "Error: Invalid username format\n");
                break;
            }
            
            int username_len = (unsigned char)buffer[1];
            char *password = getStringFromSize(buffer + 1 + 1 + username_len);
            if (!password) {
                log(ERROR, "Failed to parse password in ADD_USER");
                free(usernameToAdd);
                snprintf(response, sizeof(response), "Error: Invalid password format\n");
                break;
            }
            
            log(INFO, "Adding user: %s", usernameToAdd);
            add_user(usernameToAdd, password);
            snprintf(response, sizeof(response), "Usuario %s agregado exitosamente\n%s", usernameToAdd, getUsers());
            
            free(usernameToAdd);
            free(password);
            break;
        }
        case REMOVE_USER: {
            log(DEBUG, "Comando REMOVE_USER recibido");
            
            if (MonitoringClientData->bytes < 3) {
                log(ERROR, "Invalid REMOVE_USER message length");
                snprintf(response, sizeof(response), "Error: Invalid message format\n");
                break;
            }
            
            char *usernameToRemove = getStringFromSize(buffer + 1);
            if (!usernameToRemove) {
                log(ERROR, "Failed to parse username in REMOVE_USER");
                snprintf(response, sizeof(response), "Error: Invalid username format\n");
                break;
            }
            
            log(INFO, "Removing user: %s", usernameToRemove);
            remove_user(usernameToRemove);
            snprintf(response, sizeof(response), "Usuario %s eliminado exitosamente\n%s", usernameToRemove, getUsers());
            
            free(usernameToRemove);
            break;
        }
        
        default:
            log(DEBUG, "Comando desconocido recibido: %d", command);
            snprintf(response, sizeof(response), "Comando %d procesado\n", command);
            break;
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
        .on_arrival = stm_read_arrival,
        .on_read_ready = stm_login_read,
    },
    {
        .state = STM_LOGIN_MONITORING_WRITE,
        .on_write_ready = stm_login_write,
    },
    {
        .state = STM_REQUEST_MONITORING_READ,
        .on_arrival = stm_read_arrival,
        .on_read_ready = stm_request_read,
    },
    {
        .state = STM_REQUEST_MONITORING_WRITE,
        .on_write_ready = stm_request_write,
    },
    {
        .state = STM_MONITORING_DONE,
        .on_arrival = stm_done_arrival,
    },
    {
        .state = STM_MONITORING_ERROR,
        .on_arrival = stm_error_arrival,
    },
};

void client_handler_read(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    enum StateMonitoring state = stm_handler_read(&MonitoringClientData->stm, key);
    
    if (state == STM_MONITORING_ERROR || MonitoringClientData->connection_should_close) {
        log(DEBUG, "Closing connection for client fd=%d (state=%d, should_close=%d)", 
            key->fd, state, MonitoringClientData->connection_should_close);
        selector_unregister_fd(key->s, key->fd);
        return;
    }
}

void client_handler_write(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    enum StateMonitoring state = stm_handler_write(&MonitoringClientData->stm, key);
    
    if (state == STM_MONITORING_ERROR || MonitoringClientData->connection_should_close) {
        log(DEBUG, "Closing connection for client fd=%d (state=%d, should_close=%d)", 
            key->fd, state, MonitoringClientData->connection_should_close);
        selector_unregister_fd(key->s, key->fd);
        return;
    }
}

void client_handler_block(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    enum StateMonitoring state = stm_handler_block(&MonitoringClientData->stm, key);
    
    if (state == STM_MONITORING_ERROR || MonitoringClientData->connection_should_close) {
        log(DEBUG, "Closing connection for client fd=%d (state=%d, should_close=%d)", 
            key->fd, state, MonitoringClientData->connection_should_close);
        selector_unregister_fd(key->s, key->fd);
        return;
    }
}

void client_handler_close(struct selector_key *key) {
    MonitoringClientData *MonitoringClientData = key->data;
    log(INFO, "Closing connection for client fd=%d", key->fd);
    
    close(key->fd);
    
    if (MonitoringClientData) {
        free(MonitoringClientData);
    }
}

void handle_read_passive(struct selector_key *key) {
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

    clientHandler->handle_read = client_handler_read;
    clientHandler->handle_write = client_handler_write;
    clientHandler->handle_close = client_handler_close;
    clientHandler->handle_block = client_handler_block;

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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    setLogLevel(DEBUG);
    
    // Ignorar SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    
    log(INFO, "Starting SOCKS5 server on port %s", argv[1]);

    load_users();
    log(INFO, "Users loaded successfully");

    int servSock = setupTCPServerSocket(argv[1]);
    if (servSock < 0) {
        log(FATAL, "Failed to setup TCP server socket");
        return 1;
    }

    if (selector_fd_set_nio(servSock) < 0) {
        log(FATAL, "Could not set O_NONBLOCK on listening socket");
        close(servSock);
        return 1;
    }

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 1, .tv_nsec = 0 }
    };
    
    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        log(FATAL, "Failed to initialize selector");
        close(servSock);
        return 1;
    }

    fd_selector selector = selector_new(SELECTOR_CAPACITY);
    if (selector == NULL) {
        log(FATAL, "Failed to create selector");
        close(servSock);
        selector_close();
        return 1;
    }

    static const fd_handler listen_handler = {
        .handle_read  = handle_read_passive,
        .handle_write = NULL,
        .handle_block = NULL,
        .handle_close = NULL
    };

    if (selector_register(selector, servSock, &listen_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        log(FATAL, "Failed to register listening socket in selector");
        selector_destroy(selector);
        selector_close();
        close(servSock);
        return 1;
    }

    log(INFO, "Server started successfully, entering main loop");

    while (selector_select(selector) == SELECTOR_SUCCESS) {
        // El selector maneja todos los eventos
    }

    log(INFO, "Server shutting down");
    selector_destroy(selector);
    selector_close();
    close(servSock);
    return 0;
}