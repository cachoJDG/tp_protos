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
        log(ERROR, "malloc failed in getStringFromSize");
        return NULL;
    }
    
    memcpy(str, buffer + 1, size);
    str[size] = '\0';
    
    log(DEBUG, "Parsed string: %s (length: %d)", str, size);
    return str;
}

int handle_list_users_command(char *response, size_t response_size) {
    log(DEBUG, "Comando LIST_USERS recibido");
    snprintf(response, response_size, "%s", getUsers());
    return 0;
}

int handle_add_user_command(char *buffer, ssize_t bytes, char *response, size_t response_size) {
    log(DEBUG, "Comando ADD_USER recibido");
    
    if (bytes < 4) {
        log(ERROR, "Invalid ADD_USER message length");
        snprintf(response, response_size, "Error: Invalid message format\n");
        return -1;
    }
    
    char *usernameToAdd = getStringFromSize(buffer + 1);
    if (!usernameToAdd) {
        log(ERROR, "Failed to parse username in ADD_USER");
        snprintf(response, response_size, "Error: Invalid username format\n");
        return -1;
    }
    
    int username_len = (unsigned char)buffer[1];
    char *password = getStringFromSize(buffer + 1 + 1 + username_len);
    if (!password) {
        log(ERROR, "Failed to parse password in ADD_USER");
        free(usernameToAdd);
        snprintf(response, response_size, "Error: Invalid password format\n");
        return -1;
    }
    
    log(INFO, "Adding user: %s", usernameToAdd);
    add_user(usernameToAdd, password);
    snprintf(response, response_size, "Usuario %s agregado exitosamente\n%s", usernameToAdd, getUsers());
    
    free(usernameToAdd);
    free(password);
    return 0;
}

int handle_remove_user_command(char *buffer, ssize_t bytes, char *response, size_t response_size) {
    log(DEBUG, "Comando REMOVE_USER recibido");
    
    if (bytes < 3) {
        log(ERROR, "Invalid REMOVE_USER message length");
        snprintf(response, response_size, "Error: Invalid message format\n");
        return -1;
    }
    
    char *usernameToRemove = getStringFromSize(buffer + 1);
    if (!usernameToRemove) {
        log(ERROR, "Failed to parse username in REMOVE_USER");
        snprintf(response, response_size, "Error: Invalid username format\n");
        return -1;
    }
    
    log(INFO, "Removing user: %s", usernameToRemove);
    remove_user(usernameToRemove);
    snprintf(response, response_size, "Usuario %s eliminado exitosamente\n%s", usernameToRemove, getUsers());
    
    free(usernameToRemove);
    return 0;
}

int handle_change_password_command(char *buffer, ssize_t bytes, char *response, size_t response_size) {
    log(DEBUG, "Comando CHANGE_PASSWORD recibido");
    
    if (bytes < 4) {
        log(ERROR, "Invalid CHANGE_PASSWORD message length");
        snprintf(response, response_size, "Error: Invalid message format\n");
        return -1;
    }
    
    char *usernameToChange = getStringFromSize(buffer + 1);
    if (!usernameToChange) {
        log(ERROR, "Failed to parse username in CHANGE_PASSWORD");
        snprintf(response, response_size, "Error: Invalid username format\n");
        return -1;
    }
    
    int username_len = (unsigned char)buffer[1];
    char *newPassword = getStringFromSize(buffer + 1 + 1 + username_len);
    if (!newPassword) {
        log(ERROR, "Failed to parse new password in CHANGE_PASSWORD");
        free(usernameToChange);
        snprintf(response, response_size, "Error: Invalid password format\n");
        return -1;
    }
    
    log(INFO, "Changing password for user: %s", usernameToChange);
    change_password(usernameToChange, newPassword);
    snprintf(response, response_size, "Contraseña de usuario %s cambiada exitosamente\n%s", usernameToChange, getUsers());
    
    free(usernameToChange);
    free(newPassword);
    return 0;
}

int handle_unknown_command(char command, char *response, size_t response_size) {
    log(DEBUG, "Comando desconocido recibido: %d", command);
    snprintf(response, response_size, "Comando %d procesado\n", command);
    return 0;
}

int handle_get_metrics_command(char *response, size_t response_size) {
    log(DEBUG, "Comando GET_METRICS recibido");
    
    snprintf(response, response_size, "Conexiones totales: %zu\nConexiones concurrentes: %zu\nBytes enviados: %zu\nBytes recibidos: %zu\n", 
        getMetrics()->total_connections, getMetrics()->current_connections, getMetrics()->bytes_sent, getMetrics()->bytes_received);
    
    return 0;
}