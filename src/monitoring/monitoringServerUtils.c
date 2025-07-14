/*#include "monitoringServerUtils.h"
#include "../shared/logger.h"
#include "../users/users.h"
#include <stdlib.h>
#include <string.h>
#include "monitoringMetrics.h"

char *getStringFromSize(char *buffer) {
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
    snprintf(response + 1, response_size, "%s", users);
    response[0] = strlen(users);
    return 0;
}

int handle_add_user_command(char *buffer, ssize_t bytes, char *response, size_t response_size) {
    
    if (bytes < 4) {
        snprintf(response, response_size, "Error: Invalid message format\n");
        return -1;
    }

    int username_len = (unsigned char)buffer[1];
    if(username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        snprintf(response, response_size, "Error: Invalid username length\n");
        return -1;
    }
    
    char *usernameToAdd = getStringFromSize(buffer + 1);
    if (usernameToAdd == NULL) {
        free(usernameToAdd);
        snprintf(response, response_size, "Error: Invalid username format\n");
        return -1;
    }

    if(find_user(usernameToAdd) >= 0) {
        snprintf(response, response_size, "Error: User %s already exists\n", usernameToAdd);
        free(usernameToAdd);
        return -1;
    }
    
    int password_len = (unsigned char)buffer[1 + 1 + username_len];
    if(password_len < 1 || password_len > PASSWORD_MAX_LENGTH) {
        free(usernameToAdd);
        snprintf(response, response_size, "Error: Invalid password length\n");
        return -1;
    }

    char *password = getStringFromSize(buffer + 1 + 1 + username_len);
    if (password == NULL) {
        free(password);
        snprintf(response, response_size, "Error: Invalid password format\n");
        return -1;
    }
    
    log(INFO, "Adding user: %s", usernameToAdd);
    add_user(usernameToAdd, password);
    char *ans = "User %s added succesfully\n%s";
    response[0] = strlen(ans) + strlen(usernameToAdd) + strlen(getUsers()) - 2;
    snprintf(response + 1, response_size, ans, usernameToAdd, getUsers());
    
    free(usernameToAdd);
    free(password);
    return 0;
}

int handle_remove_user_command(char *buffer, ssize_t bytes, char *response, size_t response_size, char *username) {
    
    if (bytes < 3) {
        snprintf(response, response_size, "Error: Invalid message format\n");
        return -1;
    }

    if(get_user_role(username) != ADMIN) {
        snprintf(response, response_size, "Error: Only admins can remove users\n");
        return -1;
    }
    
    int username_len = (unsigned char)buffer[1];
    if (username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        snprintf(response, response_size, "Error: Invalid username length\n");  
        return -1;
    }

    char *usernameToRemove = getStringFromSize(buffer + 1);
    if (usernameToRemove == NULL) {
        snprintf(response, response_size, "Error: Invalid username format\n");
        return -1;
    }

    if(find_user(usernameToRemove) == -1) {
        snprintf(response, response_size, "Error: User %s does not exist\n", usernameToRemove);
        free(usernameToRemove);
        return -1;
    }
    
    log(INFO, "Removing user: %s", usernameToRemove);
    remove_user(usernameToRemove);
    char *ans = "User %s deleted\n%s";
    response[0] = strlen(ans) + strlen(usernameToRemove) + strlen(getUsers()) - 2;
    snprintf(response + 1, response_size, ans, usernameToRemove, getUsers());
    
    free(usernameToRemove);
    return 0;
}

int handle_change_password_command(char *buffer, ssize_t bytes, char *response, size_t response_size, char *username) {
    
    if (bytes < 4) {
        char *error_msg = "Error: Invalid message format\n";
        response[0] = strlen(error_msg);
        snprintf(response, response_size, error_msg);
        return -1;
    }

    if(get_user_role(username) != ADMIN) {
        char *error_msg = "Error: Only admins can remove users\n";
        response[0] = strlen(error_msg);
        snprintf(response, response_size, error_msg);
        return -1;
    }

    int username_len = (unsigned char)buffer[1];
    if (username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        char *error_msg = "Error: Invalid username length\n";
        response[0] = strlen(error_msg);
        snprintf(response, response_size, error_msg);
        return -1;
    }
    
    char *usernameToChange = getStringFromSize(buffer + 1);
    if (usernameToChange == NULL) {
        char *error_msg = "Error: Invalid username format\n";
        response[0] = strlen(error_msg);
        snprintf(response, response_size, error_msg);
        return -1;
    }

    if(find_user(usernameToChange) == -1) {
        char *error_msg = "Error: User %s does not exist\n";
        response[0] = strlen(error_msg) + strlen(usernameToChange) -2;
        snprintf(response + 1, response_size, error_msg, usernameToChange);
        free(usernameToChange);
        return -1;
    }
    
    int password_len = (unsigned char)buffer[1 + 1 + username_len];
    if (password_len < 1 || password_len > PASSWORD_MAX_LENGTH) {
        snprintf(response, response_size, "Error: Invalid password length\n");
        free(usernameToChange);
        return -1;
    }

    char *newPassword = getStringFromSize(buffer + 1 + 1 + username_len);
    if (newPassword == NULL) {
        free(usernameToChange);
        snprintf(response, response_size, "Error: Invalid password format\n");
        return -1;
    }
    
    log(INFO, "Changing password for user: %s", usernameToChange);
    change_password(usernameToChange, newPassword);
    char *ans = "Password successfully changed for user %s.\n%s";
    response[0] = strlen(ans) + strlen(usernameToChange) + strlen(getUsers()) - 2;
    snprintf(response + 1, response_size, ans, usernameToChange, getUsers());
    
    free(usernameToChange);
    free(newPassword);
    return 0;
}

int handle_unknown_command(char command, char *response, size_t response_size) {
    log(DEBUG, "Unkown command received: %d", command);
    snprintf(response, response_size, "Command %d processed\n", command);
    return 0;
}

int handle_get_metrics_command(char *response, size_t response_size) {
    
    char *ans = "Total connections: %zu\nFrequent connections: %zu\nBytes sent: %zu\nBytes received: %zu\n";
    MonitoringMetrics *metrics = getMetrics();
    response[0] = strlen(ans) + strlen(metrics->total_connections) + 
                  strlen(metrics->current_connections) + 
                  strlen(metrics->bytes_sent) + 
                  strlen(metrics->bytes_received) - 4;
    snprintf(response + 1, response_size, ans, 
             metrics->total_connections, 
             metrics->current_connections, 
             metrics->bytes_sent, 
             metrics->bytes_received);
    
    return 0;
}

int handle_change_role_command(char *buffer, ssize_t bytes, char *response, size_t response_size, char *username) {

    if (bytes < 3) {
        snprintf(response, response_size, "Error: Invalid message format\n");
        return -1;
    }

    if(get_user_role(username) != ADMIN) {
        snprintf(response, response_size, "Error: Only admins can change roles\n");
        return -1;
    }
    
    int username_len = (unsigned char)buffer[1];
    if (username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        snprintf(response, response_size, "Error: Invalid username length\n");  
        return -1;
    }

    char *usernameToChange = getStringFromSize(buffer + 1);
    if (usernameToChange == NULL) {
        snprintf(response, response_size, "Error: Invalid username format\n");
        return -1;
    }

    if(find_user(usernameToChange) == -1) {
        snprintf(response, response_size, "Error: User %s does not exist\n", usernameToChange);
        free(usernameToChange);
        return -1;
    }
    
    char newRole = buffer[1 + 1 + username_len];
    if(newRole != 0 && newRole != 1) {
        snprintf(response, response_size, "Error: Invalid role. Must be '0' (user) or '1' (admin)\n");
        free(usernameToChange);
        return -1;
    }
    
    log(INFO, "Changing role for user: %s to %c", usernameToChange, newRole);
    change_role(usernameToChange, newRole);
    char * ans = "Role successfully changed for user %s to %s.\n%s";
    response[0] = strlen(ans) + strlen(usernameToChange) + 
                  (newRole == 1 ? strlen("ADMIN") : strlen("USER")) +
                  strlen(getUsers()) - 4;
    snprintf(response + 1, response_size, ans, usernameToChange, newRole == 1 ? "ADMIN" : "USER", getUsers());
    
    free(usernameToChange);
    return 0;
}*/


#include "monitoringServerUtils.h"
#include "../shared/logger.h"
#include "../users/users.h"
#include <stdlib.h>
#include <string.h>
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

char *getStringFromSize(char *buffer) {
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
    response[0] = strlen(users);
    snprintf(response + 1, response_size - 1, "%s", users);
    return 0;
}

int handle_add_user_command(char *buffer, ssize_t bytes, char *response, size_t response_size) {
    
    if (bytes < 4) {
        char *error_msg = "Error: Invalid message format\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }

    int username_len = (unsigned char)buffer[1];
    if(username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        char *error_msg = "Error: Invalid username length\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }
    
    char *usernameToAdd = getStringFromSize(buffer + 1);
    if (usernameToAdd == NULL) {
        char *error_msg = "Error: Invalid username format\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }

    if(find_user(usernameToAdd) >= 0) {
        char *error_msg = "Error: User %s already exists\n";
        response[0] = strlen(error_msg) + strlen(usernameToAdd) - 2;
        snprintf(response + 1, response_size - 1, error_msg, usernameToAdd);
        free(usernameToAdd);
        return -1;
    }
    
    int password_len = (unsigned char)buffer[1 + 1 + username_len];
    if(password_len < 1 || password_len > PASSWORD_MAX_LENGTH) {
        char *error_msg = "Error: Invalid password length\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        free(usernameToAdd);
        return -1;
    }

    char *password = getStringFromSize(buffer + 1 + 1 + username_len);
    if (password == NULL) {
        char *error_msg = "Error: Invalid password format\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        free(usernameToAdd);
        return -1;
    }
    
    log(INFO, "Adding user: %s", usernameToAdd);
    add_user(usernameToAdd, password);
    char *ans = "User %s added successfully\n%s";
    response[0] = strlen(ans) + strlen(usernameToAdd) + strlen(getUsers()) - 4;
    snprintf(response + 1, response_size - 1, ans, usernameToAdd, getUsers());
    
    free(usernameToAdd);
    free(password);
    return 0;
}

int handle_remove_user_command(char *buffer, ssize_t bytes, char *response, size_t response_size, char *username) {
    
    if (bytes < 3) {
        char *error_msg = "Error: Invalid message format\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }

    if(get_user_role(username) != ADMIN) {
        char *error_msg = "Error: Only admins can remove users\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }
    
    int username_len = (unsigned char)buffer[1];
    if (username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        char *error_msg = "Error: Invalid username length\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }

    char *usernameToRemove = getStringFromSize(buffer + 1);
    if (usernameToRemove == NULL) {
        char *error_msg = "Error: Invalid username format\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }

    if(find_user(usernameToRemove) == -1) {
        char *error_msg = "Error: User %s does not exist\n";
        response[0] = strlen(error_msg) + strlen(usernameToRemove) - 2;
        snprintf(response + 1, response_size - 1, error_msg, usernameToRemove);
        free(usernameToRemove);
        return -1;
    }
    
    log(INFO, "Removing user: %s", usernameToRemove);
    remove_user(usernameToRemove);
    char *ans = "User %s deleted\n%s";
    response[0] = strlen(ans) + strlen(usernameToRemove) + strlen(getUsers()) - 4;
    snprintf(response + 1, response_size - 1, ans, usernameToRemove, getUsers());
    
    free(usernameToRemove);
    return 0;
}

int handle_change_password_command(char *buffer, ssize_t bytes, char *response, size_t response_size, char *username) {
    
    if (bytes < 4) {
        char *error_msg = "Error: Invalid message format\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }

    if(get_user_role(username) != ADMIN) {
        char *error_msg = "Error: Only admins can change passwords\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }

    int username_len = (unsigned char)buffer[1];
    if (username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        char *error_msg = "Error: Invalid username length\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }
    
    char *usernameToChange = getStringFromSize(buffer + 1);
    if (usernameToChange == NULL) {
        char *error_msg = "Error: Invalid username format\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }

    if(find_user(usernameToChange) == -1) {
        char *error_msg = "Error: User %s does not exist\n";
        response[0] = strlen(error_msg) + strlen(usernameToChange) - 2;
        snprintf(response + 1, response_size - 1, error_msg, usernameToChange);
        free(usernameToChange);
        return -1;
    }
    
    int password_len = (unsigned char)buffer[1 + 1 + username_len];
    if (password_len < 1 || password_len > PASSWORD_MAX_LENGTH) {
        char *error_msg = "Error: Invalid password length\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        free(usernameToChange);
        return -1;
    }

    char *newPassword = getStringFromSize(buffer + 1 + 1 + username_len);
    if (newPassword == NULL) {
        char *error_msg = "Error: Invalid password format\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        free(usernameToChange);
        return -1;
    }
    
    log(INFO, "Changing password for user: %s", usernameToChange);
    change_password(usernameToChange, newPassword);
    char *ans = "Password successfully changed for user %s.\n%s";
    response[0] = strlen(ans) + strlen(usernameToChange) + strlen(getUsers()) - 4;
    snprintf(response + 1, response_size - 1, ans, usernameToChange, getUsers());
    
    free(usernameToChange);
    free(newPassword);
    return 0;
}

int handle_unknown_command(char command, char *response, size_t response_size) {
    log(DEBUG, "Unknown command received: %d", command);
    char *ans = "Command %d processed\n";
    response[0] = strlen(ans) + count_digits(command) - 2;
    snprintf(response + 1, response_size - 1, ans, command);
    return 0;
}

int handle_get_metrics_command(char *response, size_t response_size) {
    char *ans = "Total connections: %zu\nCurrent connections: %zu\nBytes sent: %zu\nBytes received: %zu\n";
    MonitoringMetrics *metrics = getMetrics();
    
    int total_length = strlen("Total connections: \nCurrent connections: \nBytes sent: \nBytes received: \n") +
                      count_digits(metrics->total_connections) +
                      count_digits(metrics->current_connections) +
                      count_digits(metrics->bytes_sent) +
                      count_digits(metrics->bytes_received);
    
    response[0] = total_length;
    snprintf(response + 1, response_size - 1, ans,
             metrics->total_connections,
             metrics->current_connections,
             metrics->bytes_sent,
             metrics->bytes_received);
    
    return 0;
}

int handle_change_role_command(char *buffer, ssize_t bytes, char *response, size_t response_size, char *username) {

    if (bytes < 3) {
        char *error_msg = "Error: Invalid message format\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }

    if(get_user_role(username) != ADMIN) {
        char *error_msg = "Error: Only admins can change roles\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }
    
    int username_len = (unsigned char)buffer[1];
    if (username_len < 1 || username_len > UNAME_MAX_LENGTH) {
        char *error_msg = "Error: Invalid username length\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }

    char *usernameToChange = getStringFromSize(buffer + 1);
    if (usernameToChange == NULL) {
        char *error_msg = "Error: Invalid username format\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        return -1;
    }

    if(find_user(usernameToChange) == -1) {
        char *error_msg = "Error: User %s does not exist\n";
        response[0] = strlen(error_msg) + strlen(usernameToChange) - 2;
        snprintf(response + 1, response_size - 1, error_msg, usernameToChange);
        free(usernameToChange);
        return -1;
    }
    
    char newRole = buffer[1 + 1 + username_len];
    if(newRole != 0 && newRole != 1) {
        char *error_msg = "Error: Invalid role. Must be 0 (user) or 1 (admin)\n";
        response[0] = strlen(error_msg);
        snprintf(response + 1, response_size - 1, "%s", error_msg);
        free(usernameToChange);
        return -1;
    }
    
    log(INFO, "Changing role for user: %s to %d", usernameToChange, newRole);
    change_role(usernameToChange, newRole);
    
    char *ans = "Role successfully changed for user %s to %s.\n%s";
    char *role_str = (newRole == 1) ? "ADMIN" : "USER";
    response[0] = strlen(ans) + strlen(usernameToChange) + strlen(role_str) + strlen(getUsers()) - 6;
    snprintf(response + 1, response_size - 1, ans, usernameToChange, role_str, getUsers());
    
    free(usernameToChange);
    return 0;
}