#include "connectionTraffic.h"
#include <poll.h>
#include "./../shared/logger.h"
#include "./../shared/util.h"
#include <stdio.h>
#include "../buffer.h"

typedef struct ProxyData {
    int           client_fd;    // descriptor del socket del cliente SOCKS
    int           outgoing_fd; 
    struct buffer* client_buffer;  // buffer para almacenar datos del socket del cliente
    struct buffer* outgoing_buffer; // buffer para almacenar datos del socket remoto
} ProxyData;

void proxy_handler_read(struct selector_key *key);
void proxy_handler_write(struct selector_key *key);
void proxy_handler_block(struct selector_key *key);
void proxy_handler_close(struct selector_key *key);

fd_handler PROXY_HANDLER = {
    .handle_read = proxy_handler_read,
    .handle_write = proxy_handler_write,
    .handle_block = proxy_handler_block,
    .handle_close = proxy_handler_close,
};

// Acá va la parte de crear el nuevo socket (salvo que ya esté creado)
void stm_connection_traffic_arrival(const unsigned state, struct selector_key *key) {
    log(DEBUG, "stm_connection_traffic_arrival called for socket %d", key->fd);
    ClientData *clientData = key->data; 
    ssize_t received; /////////////////////////////////////////////
    int clientSocket = key->fd;
    int remoteSocket = clientData->outgoing_fd;

    // add the new socket to the selector
    ProxyData *proxyData = calloc(1, sizeof(ProxyData)); 

    clientData->client_buffer = malloc(sizeof(struct buffer));
    clientData->outgoing_buffer = malloc(sizeof(struct buffer));


    uint8_t *clientBufferData = calloc(BUFSIZE, sizeof(uint8_t));
    uint8_t *remoteBufferData = calloc(BUFSIZE, sizeof(uint8_t));


    log(DEBUG, "client buffer: %p, remote buffer: %p", (void*)clientData->client_buffer, (void*)clientData->outgoing_buffer);

    buffer_init(clientData->client_buffer, BUFSIZE, clientBufferData);
    buffer_init(clientData->outgoing_buffer, BUFSIZE, remoteBufferData);

    // Los buffers se comparten entre el cliente y el servidor remoto

    proxyData->client_fd   = clientSocket;
    proxyData->outgoing_fd = remoteSocket;

    proxyData->client_buffer = clientData->client_buffer;
    proxyData->outgoing_buffer = clientData->outgoing_buffer;

    selector_register(key->s, remoteSocket, &PROXY_HANDLER, OP_READ, (void *)proxyData);
}

// BUFFER CLIENTE --> SOCKET REMOTO
unsigned stm_connection_traffic_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    size_t readable;
    uint8_t *read_ptr = buffer_read_ptr(clientData->outgoing_buffer, &readable);
    ssize_t bytesWritten = send(key->fd, read_ptr, readable, 0);
    if (bytesWritten <= 0) {
        log(ERROR, "Error writing to socket %d: %zd", key->fd, bytesWritten);
        return STM_DONE;
    }
    buffer_read_adv(clientData->outgoing_buffer, bytesWritten);
    if (buffer_can_read(clientData->outgoing_buffer)) {
        selector_set_interest(key->s, clientData->client_fd, OP_READ | OP_WRITE);
    } else {
        selector_set_interest(key->s, clientData->client_fd, OP_READ);
    }

    log(DEBUG, "Write handler called for socket %d [CLIENT]", key->fd);
    return STM_CONNECTION_TRAFFIC;
}

// SOCKET CLIENTE --> BUFFER CLIENTE
unsigned stm_connection_traffic_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(clientData->client_buffer, &available);

    ssize_t bytesRead = recv(key->fd, write_ptr, available, 0);
    if (bytesRead <= 0) {
        if (bytesRead == 0) {
            log(INFO, "Connection closed by peer on socket %d", key->fd);
        } else {
            log(ERROR, "Error reading from socket %d: %s", key->fd, strerror(errno));
        }
        
        return STM_DONE;
    }

    buffer_write_adv(clientData->client_buffer, bytesRead);
    if (buffer_can_read(clientData->client_buffer)) {
        selector_set_interest(key->s, clientData->outgoing_fd, OP_READ | OP_WRITE);
    } else {
        selector_set_interest(key->s, clientData->outgoing_fd, OP_READ);
    }
    log(DEBUG, "Received %zd bytes from socket %d [CLIENT]", bytesRead, key->fd);
    return STM_CONNECTION_TRAFFIC;
}

void stm_connection_traffic_departure(const unsigned state, struct selector_key *key) {
    log(DEBUG, "stm_connection_traffic_departure called for socket %d", key->fd);
    ClientData *clientData = key->data;
    // hacer frees acá (creo)
        
    // Close outgoing socket
    close(clientData->outgoing_fd);

    // Free allocated shared buffers
    free(clientData->client_buffer->data);
    free(clientData->outgoing_buffer->data);
    free(clientData->client_buffer);
    free(clientData->outgoing_buffer);

    //TODO: OJO porque solo estuve tratando de cerrar la conexión del proxy, pero uno puede seguir hablando con el cliente

    // Por ahora, decidí cerrar la conexión del cliente acá. Habría que ver qué hacer con esto
    close(clientData->client_fd);
}

// SOCKET REMOTO --> BUFFER REMOTO
void proxy_handler_read(struct selector_key *key) {
    ProxyData *proxyData = key->data;
    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(proxyData->outgoing_buffer, &available);

    ssize_t bytesRead = recv(key->fd, write_ptr, available, 0);
    if (bytesRead <= 0) {
        log(ERROR, "Error reading from socket %d: %zd", key->fd, bytesRead);
        close(key->fd);
        // TODO: avisarle al cliente que se cerró la conexión
        return;
    }

    buffer_write_adv(proxyData->outgoing_buffer, bytesRead);
    if (buffer_can_read(proxyData->outgoing_buffer)) {
        selector_set_interest(key->s, proxyData->client_fd, OP_READ | OP_WRITE);
    } else {
        selector_set_interest(key->s, proxyData->client_fd, OP_READ);
    }

    log(DEBUG, "Received %zd bytes from socket %d [REMOTE]", bytesRead, key->fd);
}

// BUFFER REMOTO --> SOCKET CLIENTE
void proxy_handler_write(struct selector_key *key) {
    ProxyData *proxyData = key->data;
    size_t readable;
    uint8_t *read_ptr = buffer_read_ptr(proxyData->client_buffer, &readable);
    ssize_t bytesWritten = send(key->fd, read_ptr, readable, 0);
    if (bytesWritten <= 0) {
        log(ERROR, "Error writing to socket %d: %zd", key->fd, bytesWritten);
        close(key->fd);
        // TODO: avisarle al cliente que se cerró la conexión

        return;
    }
    buffer_read_adv(proxyData->client_buffer, bytesWritten);
    if (buffer_can_read(proxyData->client_buffer)) {
        selector_set_interest(key->s, proxyData->outgoing_fd, OP_READ | OP_WRITE);
    } else {
        selector_set_interest(key->s, proxyData->outgoing_fd, OP_READ);
    }

    log(DEBUG, "Write handler called for socket %d [REMOTE]", key->fd);
    return;
}

void proxy_handler_block(struct selector_key *key) {
    log(DEBUG, "Block Handler called for socket %d", key->fd);
}

void proxy_handler_close(struct selector_key *key) {
    ProxyData *proxyData = key->data;
    log(INFO, "Closing proxy connection for client %d", proxyData->client_fd);
    // Hacer frees específicos del outgoing_fd

    // Free the ProxyData structure
    free(proxyData);
    
    // Unregister the file descriptor from the selector
    selector_unregister_fd(key->s, key->fd);
}

