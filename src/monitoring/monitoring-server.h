#ifndef MONITORING_H
#define MONITORING_H

#include <sys/socket.h>
#include <netdb.h>
#include "../selector.h"
#include "../stm.h"
#include "../buffer.h"
#include <stdbool.h> // Necesario para el tipo bool

// Constants
#define BUFSIZE_MONITORING 256
#define MAX_ADDR_BUFFER_MONITORING 128
#define UNAME_MAX_LENGTH 64
#define PASSWORD_MAX_LENGTH 64

// Command definitions
enum MonitoringCommands {
    LIST_USERS = 1,
    ADD_USER = 2,
    REMOVE_USER = 3,
    CHANGE_PASSWORD = 4,
    GET_METRICS = 5,
    CHANGE_ROLE = 6
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

// Login Parsing States (usados para el campo parsing_state como enteros)
enum LoginParsingStates {
    LOGIN_PARSE_VERSION_AND_UNAME_LEN = 0, // Espera la versión y longitud del username
    LOGIN_PARSE_UNAME_AND_PASS_LEN,        // Espera el username y longitud del password
    LOGIN_PARSE_PASSWORD_BYTES,            // Espera los bytes de la contraseña
    LOGIN_PARSE_DONE                       // Indica que el parsing del login ha terminado
};

// Request Parsing States (usados para el campo parsing_state como enteros)
enum RequestParsingStates {
    REQUEST_PARSE_COMMAND_TYPE = 0,         // Estado inicial: espera el byte del comando
    REQUEST_PARSE_ADD_CHANGE_UNAME_LEN,     // Para ADD_USER, CHANGE_PASSWORD: espera longitud de username
    REQUEST_PARSE_ADD_CHANGE_UNAME,         // Para ADD_USER, CHANGE_PASSWORD: espera el username
    REQUEST_PARSE_ADD_CHANGE_PASS_LEN,      // Para ADD_USER, CHANGE_PASSWORD: espera longitud de password
    REQUEST_PARSE_ADD_CHANGE_PASS,          // Para ADD_USER, CHANGE_PASSWORD: espera el password
    REQUEST_PARSE_REMOVE_UNAME_LEN,         // Para REMOVE_USER: espera longitud de username
    REQUEST_PARSE_REMOVE_UNAME,             // Para REMOVE_USER: espera el username
    REQUEST_PARSE_CHANGE_ROLE_UNAME_LEN,    // Para CHANGE_ROLE: espera longitud de username
    REQUEST_PARSE_CHANGE_ROLE_UNAME_AND_ROLE, // Para CHANGE_ROLE: espera username y rol
    REQUEST_PARSE_DONE                      // Indica que el parsing del request ha terminado
};


// Client data structure
typedef struct MonitoringClientData {
   uint8_t buffer[BUFSIZE_MONITORING];
   ssize_t bytes;
   struct state_machine stm;
   char username[UNAME_MAX_LENGTH];
   char password[UNAME_MAX_LENGTH];
   int connection_should_close;
   buffer client_buffer;           // Buffer para acumular datos
   ssize_t toRead;                // Bytes que faltan por leer para el paso actual
   int parsing_state;             // Usaremos enteros simples para los estados de parsing
   size_t expected_message_size;  // Tamaño esperado del mensaje completo (e.g., longitud de username/password)
   fd_handler handler;
   uint8_t buffer_data[BUFSIZE_MONITORING]; // Buffer de datos para la lectura, los que no se encuentran parseados todavia.
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
