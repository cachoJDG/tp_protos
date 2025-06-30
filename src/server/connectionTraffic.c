#include "connectionTraffic.h"
#include <poll.h>
#include "./../shared/logger.h"
#include "./../shared/util.h"
#include <stdio.h>
#include "../buffer.h"
#include "sockUtils.h"


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

    int clientSocket = key->fd;
    int remoteSocket = clientData->outgoing_fd;

    buffer_init(&clientData->outgoing_buffer, BUFSIZE, clientData->remoteBufferData);

    // Los buffers se comparten entre el cliente y el servidor remoto
    selector_register(key->s, remoteSocket, &PROXY_HANDLER, OP_READ, key->data); // Comparto el contexto
}

// BUFFER CLIENTE --> SOCKET REMOTO
unsigned stm_connection_traffic_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    size_t readable;
    uint8_t *read_ptr = buffer_read_ptr(&clientData->outgoing_buffer, &readable);
    ssize_t bytesWritten = sendBytesWithMetrics(key->fd, read_ptr, readable, 0);
    if (bytesWritten <= 0) {
        log(ERROR, "Error writing to socket %d: %zd", key->fd, bytesWritten);
        return STM_DONE;
    }
    buffer_read_adv(&clientData->outgoing_buffer, bytesWritten);
    if (buffer_can_read(&clientData->outgoing_buffer)) {
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
    uint8_t *write_ptr = buffer_write_ptr(&clientData->client_buffer, &available);

    ssize_t bytesRead = recvBytesWithMetrics(key->fd, write_ptr, available, 0);
    if (bytesRead <= 0) {
        if (bytesRead == 0) {
            log(INFO, "Connection closed by peer on socket %d", key->fd);
        } else {
            log(ERROR, "Error reading from socket %d: %s", key->fd, strerror(errno));
        }
        
        return STM_DONE;
    }

    buffer_write_adv(&clientData->client_buffer, bytesRead);
    if (buffer_can_read(&clientData->client_buffer)) {
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
        
    // Close outgoing socket
    selector_unregister_fd(key->s, clientData->outgoing_fd);
    clientData->outgoing_fd = -1; // Reset outgoing_fd to indicate no active connection
}

// SOCKET REMOTO --> BUFFER REMOTO
void proxy_handler_read(struct selector_key *key) {
    ClientData *proxyData = key->data;
    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(&proxyData->outgoing_buffer, &available);

    ssize_t bytesRead = recvBytesWithMetrics(key->fd, write_ptr, available, 0);
    if (bytesRead <= 0) {
        log(ERROR, "Error reading from socket %d: %zd", key->fd, bytesRead);
        selector_unregister_fd(key->s, key->fd);
        // TODO: avisarle al cliente que se cerró la conexión
        return;
    }

    buffer_write_adv(&proxyData->outgoing_buffer, bytesRead);
    if (buffer_can_read(&proxyData->outgoing_buffer)) {
        selector_set_interest(key->s, proxyData->client_fd, OP_READ | OP_WRITE);
    } else {
        selector_set_interest(key->s, proxyData->client_fd, OP_READ);
    }

    log(DEBUG, "Received %zd bytes from socket %d [REMOTE]", bytesRead, key->fd);
}

// BUFFER REMOTO --> SOCKET CLIENTE
void proxy_handler_write(struct selector_key *key) {
    ClientData *proxyData = key->data;
    size_t readable;
    uint8_t *read_ptr = buffer_read_ptr(&proxyData->client_buffer, &readable);
    ssize_t bytesWritten = sendBytesWithMetrics(key->fd, read_ptr, readable, 0);
    if (bytesWritten <= 0) {
        log(ERROR, "Error writing to socket %d: %zd", key->fd, bytesWritten);
        selector_unregister_fd(key->s, key->fd);
        // TODO: avisarle al cliente que se cerró la conexión

        return;
    }
    buffer_read_adv(&proxyData->client_buffer, bytesWritten);
    if (buffer_can_read(&proxyData->client_buffer)) {
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
    if (key->data == NULL) {
        log(ERROR, "proxy_handler_close called with NULL data");
        return;
    }
    log(INFO, "Closing proxy connection for proxy %d", key->fd);
    closeSocketWithMetrics(key->fd);
}

