#ifndef MONITORING_H
#define MONITORING_H

#include <sys/socket.h>
#include <netdb.h>
#include "../selector.h"
#include "../stm.h"
#include "../buffer.h"

// Constants
// #define MAXPENDING 5
#define BUFSIZE_MONITORING 512
#define MAX_ADDR_BUFFER_MONITORING 128
#define UNAME_MAX_LENGTH 256
#define PASSWORD_MAX_LENGTH 256
// #define SELECTOR_CAPACITY 256

// Command definitions
enum MonitoringCommands {
    LIST_USERS = 1,
    ADD_USER = 2,
    REMOVE_USER = 3,
    CHANGE_PASSWORD = 4,
    GET_METRICS = 5
};

// State machine states for monitoring protocol
enum StateMonitoring {
    STM_LOGIN_MONITORING_READ,
    STM_LOGIN_MONITORING_WRITE,
    STM_REQUEST_MONITORING_READ,
    STM_REQUEST_MONITORING_WRITE,
    STM_MONITORING_DONE,
    STM_MONITORING_ERROR,
};

// Client data structure
typedef struct MonitoringClientData {
    char buffer[BUFSIZE_MONITORING];
    ssize_t bytes;
    struct state_machine stm;
    char username[64];
    char password[64];
    int connection_should_close;
    buffer client_buffer;           // Buffer para acumular datos
    uint8_t buffer_data[BUFSIZE_MONITORING];  // Array de datos del buffer
    ssize_t toRead;                // Bytes que faltan por leer
    int parsing_state;             // Estado del parsing (0=esperando comando, 1=leyendo datos)
    size_t expected_message_size;  // Tamaño esperado del mensaje completo
    fd_handler handler;
} MonitoringClientData;

// Public function declarations

/**
 * Accepts a TCP connection from a client
 * @param servSock Server socket file descriptor
 * @return Client socket file descriptor on success, -1 on error
 */
int acceptTCPConnection(int servSock);

/**
 * Prints buffer contents in hexadecimal format for debugging
 * @param label Description label for the buffer
 * @param buffer Buffer to print
 * @param length Length of the buffer
 */
void print_hex_compact(const char* label, const unsigned char* buffer, size_t length);

/**
 * Extracts a length-prefixed string from a buffer
 * @param buffer Buffer containing length-prefixed string
 * @return Allocated string on success, NULL on error (caller must free)
 */
char *getStringFromSize(char *buffer);

// State machine handlers
void stm_read_monitoring_arrival(unsigned state, struct selector_key *key);
void stm_error_monitoring_arrival(unsigned state, struct selector_key *key);
void stm_done_monitoring_arrival(unsigned state, struct selector_key *key);

// Protocol state handlers
enum StateMonitoring stm_login_monitoring_read(struct selector_key *key);
enum StateMonitoring stm_login_monitoring_write(struct selector_key *key);
enum StateMonitoring stm_request_monitoring_read(struct selector_key *key);
enum StateMonitoring stm_request_monitoring_write(struct selector_key *key);

// Client connection handlers
void client_handler_monitoring_read(struct selector_key *key);
void client_handler_monitoring_write(struct selector_key *key);
void client_handler_monitoring_block(struct selector_key *key);
void client_handler_monitoring_close(struct selector_key *key);

/**
 * Handles new incoming connections on the passive socket
 * @param key Selector key for the listening socket
 */
void handle_read_passive_monitoring(struct selector_key *key);

// External global variables (if needed by other modules)
extern struct sockaddr_storage _localAddr;

#endif // MONITORING_H