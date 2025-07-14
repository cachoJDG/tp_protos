#include "monitoringServerUtils.h"
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
    snprintf(response, response_size, "%s", getUsers());
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
    snprintf(response, response_size, "User %s added succesfully\n%s", usernameToAdd, getUsers());
    
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
    snprintf(response, response_size, "User %s deleted\n%s", usernameToRemove, getUsers());
    
    free(usernameToRemove);
    return 0;
}

int handle_change_password_command(char *buffer, ssize_t bytes, char *response, size_t response_size, char *username) {
    
    if (bytes < 4) {
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
    snprintf(response, response_size, "Password successfully changed for user %s.\n%s", usernameToChange, getUsers());
    
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
    
    snprintf(response, response_size, "Total connections: %zu\nFrequent connections: %zu\nBytes sent: %zu\nBytes received: %zu\n", 
        getMetrics()->total_connections, getMetrics()->current_connections, getMetrics()->bytes_sent, getMetrics()->bytes_received);
    
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
    
    snprintf(response, response_size, "Role successfully changed for user %s to %s.\n%s", usernameToChange, newRole == 1 ? "ADMIN" : "USER", getUsers());
    
    free(usernameToChange);
    return 0;
}