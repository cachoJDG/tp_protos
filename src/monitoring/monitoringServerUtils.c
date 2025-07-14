#include "monitoringServerUtils.h"
#include "../shared/logger.h"
#include "../users/users.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>  // Para htons()
#include "monitoringMetrics.h"

// Función auxiliar para contar dígitos de un número
int count_digits(size_t num) {
    if (num == 0) return 1;
    int count = 0;
    while (num > 0) {
        count++;
        num /= 10;
    }
    return count;
}

// Función auxiliar para escribir la longitud en 2 bytes (network byte order)
void write_length_to_response(char *response, uint16_t length) {
    uint16_t length_net = htons(length);  // Host to Network Short
    memcpy(response, &length_net, 2);
}

char *getStringFromSize(uint8_t *buffer) {
    if (!buffer) return NULL;
    
    unsigned char size = (unsigned char)buffer[0];
    if (size == 0) return NULL;
    
    char *str = malloc(size + 1);
    if (str == NULL) {
        return NULL;
    }
    
    memcpy(str, buffer + 1, size);
    str[size] = '\0';
    
    log(DEBUG, "Parsed string: %s (length: %d)", str, size);
    return str;
}

int handle_list_users_command(char *response, size_t response_size) {
    char *users = getUsers();
    uint16_t length = strlen(users);
    write_length_to_response(response, length);
    snprintf(response + 2, response_size - 2, "%s", users);
    return 0;
}

int handle_add_user_command(uint8_t *buffer, ssize_t bytes, char *response, size_t response_size) {
    
    if (bytes < 4) {
        char *error_msg = "Error: Invalid message format\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }

    int username_len = (unsigned char)buffer[1];
    if(username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        char *error_msg = "Error: Invalid username length\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }
    
    char *usernameToAdd = getStringFromSize(buffer + 1);
    if (usernameToAdd == NULL) {
        char *error_msg = "Error: Invalid username format\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }

    if(find_user(usernameToAdd) >= 0) {
        char *error_msg = "Error: User %s already exists\n";
        uint16_t length = strlen(error_msg) + strlen(usernameToAdd) - 2;
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, error_msg, usernameToAdd);
        free(usernameToAdd);
        return -1;
    }
    
    int password_len = (unsigned char)buffer[1 + 1 + username_len];
    if(password_len < 1 || password_len > PASSWORD_MAX_LENGTH) {
        char *error_msg = "Error: Invalid password length\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        free(usernameToAdd);
        return -1;
    }

    char *password = getStringFromSize(buffer + 1 + 1 + username_len);
    if (password == NULL) {
        char *error_msg = "Error: Invalid password format\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        free(usernameToAdd);
        return -1;
    }
    
    log(INFO, "Adding user: %s", usernameToAdd);
    add_user(usernameToAdd, password);
    char *ans = "User %s added successfully\n%s";
    uint16_t length = strlen(ans) + strlen(usernameToAdd) + strlen(getUsers()) - 4;
    write_length_to_response(response, length);
    snprintf(response + 2, response_size - 2, ans, usernameToAdd, getUsers());
    
    free(usernameToAdd);
    free(password);
    return 0;
}

int handle_remove_user_command(uint8_t *buffer, ssize_t bytes, char *response, size_t response_size, char *username) {
    
    if (bytes < 3) {
        char *error_msg = "Error: Invalid message format\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }

    if(get_user_role(username) != ADMIN) {
        char *error_msg = "Error: Only admins can remove users\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }
    
    int username_len = (unsigned char)buffer[1];
    if (username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        char *error_msg = "Error: Invalid username length\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }

    char *usernameToRemove = getStringFromSize(buffer + 1);
    if (usernameToRemove == NULL) {
        char *error_msg = "Error: Invalid username format\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }

    if(find_user(usernameToRemove) == -1) {
        char *error_msg = "Error: User %s does not exist\n";
        uint16_t length = strlen(error_msg) + strlen(usernameToRemove) - 2;
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, error_msg, usernameToRemove);
        free(usernameToRemove);
        return -1;
    }
    
    log(INFO, "Removing user: %s", usernameToRemove);
    remove_user(usernameToRemove);
    char *ans = "User %s deleted\n%s";
    uint16_t length = strlen(ans) + strlen(usernameToRemove) + strlen(getUsers()) - 4;
    write_length_to_response(response, length);
    snprintf(response + 2, response_size - 2, ans, usernameToRemove, getUsers());
    
    free(usernameToRemove);
    return 0;
}

int handle_change_password_command(uint8_t *buffer, ssize_t bytes, char *response, size_t response_size, char *username) {
    
    if (bytes < 4) {
        char *error_msg = "Error: Invalid message format\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }

    if(get_user_role(username) != ADMIN) {
        char *error_msg = "Error: Only admins can change passwords\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }

    int username_len = (unsigned char)buffer[1];
    if (username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        char *error_msg = "Error: Invalid username length\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }
    
    char *usernameToChange = getStringFromSize(buffer + 1);
    if (usernameToChange == NULL) {
        char *error_msg = "Error: Invalid username format\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }

    if(find_user(usernameToChange) == -1) {
        char *error_msg = "Error: User %s does not exist\n";
        uint16_t length = strlen(error_msg) + strlen(usernameToChange) - 2;
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, error_msg, usernameToChange);
        free(usernameToChange);
        return -1;
    }
    
    int password_len = (unsigned char)buffer[1 + 1 + username_len];
    if (password_len < 1 || password_len > PASSWORD_MAX_LENGTH) {
        char *error_msg = "Error: Invalid password length\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        free(usernameToChange);
        return -1;
    }

    char *newPassword = getStringFromSize(buffer + 1 + 1 + username_len);
    if (newPassword == NULL) {
        char *error_msg = "Error: Invalid password format\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        free(usernameToChange);
        return -1;
    }
    
    log(INFO, "Changing password for user: %s", usernameToChange);
    change_password(usernameToChange, newPassword);
    char *ans = "Password successfully changed for user %s.\n%s";
    uint16_t length = strlen(ans) + strlen(usernameToChange) + strlen(getUsers()) - 4;
    write_length_to_response(response, length);
    snprintf(response + 2, response_size - 2, ans, usernameToChange, getUsers());
    
    free(usernameToChange);
    free(newPassword);
    return 0;
}

int handle_unknown_command(char command, char *response, size_t response_size) {
    log(DEBUG, "Unknown command received: %d", command);
    char *ans = "Unknown command received\n";
    uint16_t length = strlen(ans) + count_digits(command) - 2;
    write_length_to_response(response, length);
    snprintf(response + 2, response_size - 2, ans, command);
    return 0;
}

int handle_get_metrics_command(char *response, size_t response_size) {
    char *ans = "Total connections: %zu\nCurrent connections: %zu\nBytes sent: %zu\nBytes received: %zu\n";
    MonitoringMetrics *metrics = getMetrics();
    
    uint16_t total_length = strlen("Total connections: \nCurrent connections: \nBytes sent: \nBytes received: \n") +
                           count_digits(metrics->total_connections) +
                           count_digits(metrics->current_connections) +
                           count_digits(metrics->bytes_sent) +
                           count_digits(metrics->bytes_received);
    
    write_length_to_response(response, total_length);
    snprintf(response + 2, response_size - 2, ans,
             metrics->total_connections,
             metrics->current_connections,
             metrics->bytes_sent,
             metrics->bytes_received);
    
    return 0;
}

int handle_change_role_command(uint8_t *buffer, ssize_t bytes, char *response, size_t response_size, char *username) {

    if (bytes < 3) {
        char *error_msg = "Error: Invalid message format\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }

    if(get_user_role(username) != ADMIN) {
        char *error_msg = "Error: Only admins can change roles\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }
    
    int username_len = (unsigned char)buffer[1];
    if (username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        char *error_msg = "Error: Invalid username length\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }

    char *usernameToChange = getStringFromSize(buffer + 1);
    if (usernameToChange == NULL) {
        char *error_msg = "Error: Invalid username format\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        return -1;
    }

    if(find_user(usernameToChange) == -1) {
        char *error_msg = "Error: User %s does not exist\n";
        uint16_t length = strlen(error_msg) + strlen(usernameToChange) - 2;
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, error_msg, usernameToChange);
        free(usernameToChange);
        return -1;
    }
    
    char newRole = buffer[1 + 1 + username_len];
    if(newRole != 0 && newRole != 1) {
        char *error_msg = "Error: Invalid role. Must be 0 (user) or 1 (admin)\n";
        uint16_t length = strlen(error_msg);
        write_length_to_response(response, length);
        snprintf(response + 2, response_size - 2, "%s", error_msg);
        free(usernameToChange);
        return -1;
    }
    
    log(INFO, "Changing role for user: %s to %d", usernameToChange, newRole);
    change_role(usernameToChange, newRole);
    
    char *ans = "Role successfully changed for user %s to %s.\n%s";
    char *role_str = (newRole == 1) ? "ADMIN" : "USER";
    uint16_t length = strlen(ans) + strlen(usernameToChange) + strlen(role_str) + strlen(getUsers()) - 6;
    write_length_to_response(response, length);
    snprintf(response + 2, response_size - 2, ans, usernameToChange, role_str, getUsers());
    
    free(usernameToChange);
    return 0;
}