#ifndef MONITORING_COMMANDS_H
#define MONITORING_COMMANDS_H

#include "monitoring-server.h"

// Command response buffer size
#define RESPONSE_BUFFER_SIZE 65536

/**
 * Processes a LIST_USERS command
 * @param response Buffer to store the response
 * @param response_size Size of the response buffer
 * @return 0 on success, -1 on error
 */
int handle_list_users_command(char *response, size_t response_size);

/**
 * Processes an ADD_USER command
 * @param buffer Command buffer containing username and password
 * @param bytes Total bytes received
 * @param response Buffer to store the response
 * @param response_size Size of the response buffer
 * @return 0 on success, -1 on error
 */
int handle_add_user_command(uint8_t *buffer, ssize_t bytes, char *response, size_t response_size);

/**
 * Processes a REMOVE_USER command
 * @param buffer Command buffer containing username
 * @param bytes Total bytes received
 * @param response Buffer to store the response
 * @param response_size Size of the response buffer
 * @return 0 on success, -1 on error
 */
int handle_remove_user_command(uint8_t *buffer, ssize_t bytes, char *response, size_t response_size, char *username);

/**
 * Processes a CHANGE_PASSWORD command
 * @param buffer Command buffer containing username and new password
 * @param bytes Total bytes received
 * @param response Buffer to store the response
 * @param response_size Size of the response buffer
 * @return 0 on success, -1 on error
 */
int handle_change_password_command(uint8_t *buffer, ssize_t bytes, char *response, size_t response_size, char *username);

/**
 * Processes an unknown command
 * @param command Command code
 * @param response Buffer to store the response
 * @param response_size Size of the response buffer
 * @return 0 on success, -1 on error
 */
int handle_unknown_command(char command, char *response, size_t response_size);

/**
 * Utility function to extract a length-prefixed string from buffer
 * @param buffer Buffer containing length-prefixed string
 * @return Allocated string on success, NULL on error (caller must free)
 */
char *getStringFromSize(uint8_t *buffer);

/**
 * Processes a GET_METRICS command
 * @param response Buffer to store the response
 * @param response_size Size of the response buffer
 * @return 0 on success, -1 on error
 */
int handle_get_metrics_command(char *response, size_t response_size);

/**
 * Processes a CHANGE_ROLE command
 * @param buffer Command buffer containing username and new role
 * @param bytes Total bytes received
 * @param response Buffer to store the response
 * @param response_size Size of the response buffer
 * @param username Username of the user executing the command
 * @return 0 on success, -1 on error
 */
int handle_change_role_command(uint8_t *buffer, ssize_t bytes, char *response, size_t response_size, char *username);

#endif // MONITORING_COMMANDS_H