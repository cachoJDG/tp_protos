#include "connectionTraffic.h"
#include <poll.h>
#include "./../shared/logger.h"
#include "./../shared/util.h"
#include <stdio.h>
#include "../buffer.h"
#include "sockUtils.h"




// Acá va la parte de crear el nuevo socket (salvo que ya esté creado)
void stm_connection_traffic_arrival(const unsigned state, struct selector_key *key) {
    // log(DEBUG, "stm_connection_traffic_arrival called for socket %d", key->fd);
    ClientData *clientData = key->data; 

    // int clientSocket = key->fd;
    // int remoteSocket = clientData->outgoing_fd;

    buffer_init(&clientData->outgoing_buffer, BUFSIZE, clientData->remoteBufferData);

    // Los buffers se comparten entre el cliente y el servidor remoto
    selector_set_interest_key(key, OP_READ); // Dejo de escuchar el socket del cliente
    // selector_register(key->s, remoteSocket, &PROXY_HANDLER, OP_READ, key->data); // Comparto el contexto
}

// BUFFER REMOTO --> SOCKET CLIENTE
unsigned stm_connection_traffic_write(struct selector_key *key) {
    ClientData *clientData = key->data;
    size_t readable;
    uint8_t *read_ptr = buffer_read_ptr(&clientData->outgoing_buffer, &readable);

    errno = 0;
    ssize_t bytesWritten = sendBytesWithMetrics(clientData->client_fd, read_ptr, readable, 0);
    if (bytesWritten <= 0) {
        if (bytesWritten == 0) {
            log(ERROR, "[CLIENT] Error writing to socket %d: Unknown Error", clientData->client_fd);
            selector_set_interest(key->s, clientData->client_fd, OP_NOOP);
            selector_set_interest(key->s, clientData->outgoing_fd, OP_NOOP);
            return STM_DONE;
        }
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            // log(DEBUG, "Socket %d would block, not writing", clientData->client_fd);
            // No cambio nada (ni si quiera el interest)
            errno = 0;
            return STM_CONNECTION_TRAFFIC;
        }
        log(ERROR, "[CLIENT] Error writing to socket %d: %s", clientData->client_fd, strerror(errno));
        errno = 0;
        selector_set_interest(key->s, clientData->client_fd, OP_NOOP);
        selector_set_interest(key->s, clientData->outgoing_fd, OP_NOOP);
        return STM_DONE;
    }

    buffer_read_adv(&clientData->outgoing_buffer, bytesWritten);

    if (!buffer_can_read(&clientData->outgoing_buffer) && clientData->outgoing_closed) {
        // Si no hay datos para escribir y el socket remoto está cerrado, dejo de escuchar
        selector_set_interest(key->s, clientData->client_fd, OP_NOOP);
        selector_set_interest(key->s, clientData->outgoing_fd, OP_NOOP);
        log(DEBUG, "No more data to write to client %d, closing connection", clientData->client_fd);
        return STM_DONE;
    }


    if (buffer_can_read(&clientData->outgoing_buffer)) {
        selector_set_interest(key->s, clientData->client_fd, OP_READ | OP_WRITE);
    } else if (buffer_can_read(&clientData->outgoing_buffer) && clientData->outgoing_closed) {
        selector_set_interest(key->s, clientData->client_fd, OP_WRITE);

    } else {
        selector_set_interest(key->s, clientData->client_fd, OP_READ);
    }
    return STM_CONNECTION_TRAFFIC;
}

// SOCKET CLIENTE --> BUFFER CLIENTE
unsigned stm_connection_traffic_read(struct selector_key *key) {
    ClientData *clientData = key->data;
    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(&clientData->client_buffer, &available);

    errno = 0;
    ssize_t bytesRead = recvBytesWithMetrics(key->fd, write_ptr, available, 0);
    if (bytesRead <= 0) {
        if (errno == 0 && bytesRead == 0) {
            log(DEBUG, "Connection closed by peer [CLIENT] on socket %d. Operating in write mode", key->fd);
            // Freno:
            // 1. SOCKET CLIENTE --> BUFFER CLIENTE
            // 2. BUFFER CLIENTE --> SOCKET REMOTO
            // 3. SOCKET REMOTO --> BUFFER REMOTO
            // 4. BUFFER REMOTO --> SOCKET CLIENTE
            // Dejo:
            // nada
            selector_set_interest(key->s, key->fd, OP_NOOP);
            selector_set_interest(key->s, clientData->outgoing_fd, OP_NOOP);
            return STM_DONE;
        }
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            // log(DEBUG, "Socket %d would block, not reading", key->fd);
            // No cambio nada (ni si quiera el interest)
            errno = 0;
            return STM_CONNECTION_TRAFFIC;
        }
        log(ERROR, "[CLIENT] Error reading from socket %d: %s", key->fd, strerror(errno));
        errno = 0;
        selector_set_interest(key->s, key->fd, OP_NOOP);
        selector_set_interest(key->s, clientData->outgoing_fd, OP_NOOP);
        return STM_DONE;
    }

    buffer_write_adv(&clientData->client_buffer, bytesRead);

    selector_set_interest(key->s, clientData->outgoing_fd, OP_READ | OP_WRITE);
    // return stm_connection_traffic_write(key); // Ahorra un Select
    proxy_handler_write(key); // Ahorra un Select
    return STM_CONNECTION_TRAFFIC;
}

void stm_connection_traffic_departure(const unsigned state, struct selector_key *key) {
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
        if (errno == 0 && bytesRead == 0) {
            log(DEBUG, "Connection closed by peer [SERVER] on socket %d", key->fd);
            // Freno:
            // 1. SOCKET CLIENTE --> BUFFER CLIENTE
            // 2. BUFFER CLIENTE --> SOCKET REMOTO
            // 3. SOCKET REMOTO --> BUFFER REMOTO
            // Dejo:
            // 1. BUFFER REMOTO --> SOCKET CLIENTE [Si hay para escribir]
            if (buffer_can_read(&proxyData->outgoing_buffer)) {
               selector_set_interest(key->s, proxyData->client_fd, OP_WRITE);
            } else {
                selector_set_interest(key->s, proxyData->client_fd, OP_NOOP);
            }
            selector_set_interest(key->s, proxyData->outgoing_fd, OP_NOOP);
            proxyData->outgoing_closed = 1; // Indica que el socket remoto se cerró
            return;
        }
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            // log(DEBUG, "Socket %d would block, not reading", key->fd);
            // No cambio nada (ni si quiera el interest)
            return;
        }
        log(ERROR, "[SERVER] Error reading from socket %d: %s", key->fd, strerror(errno));
        selector_unregister_fd(key->s, key->fd);
        proxyData->outgoing_fd = -1; // Reset outgoing_fd to indicate no active connection
        return;
    }

    buffer_write_adv(&proxyData->outgoing_buffer, bytesRead);
    selector_set_interest(key->s, proxyData->client_fd, OP_READ | OP_WRITE);

    unsigned state = stm_connection_traffic_write(key); // Ahorra un Select
    if (state == STM_ERROR || state == STM_DONE) {
        selector_unregister_fd(key->s, proxyData->outgoing_fd);
        proxyData->outgoing_fd = -1;
    }
}

// BUFFER CLIENTE --> SOCKET REMOTO
// Ojo: NO USAR key->fd, para no asumir qué socket es
void proxy_handler_write(struct selector_key *key) {
    ClientData *proxyData = key->data;

    if (proxyData->server_is_connecting) {
        selector_set_interest(key->s, proxyData->client_fd, OP_WRITE);
        return;
    }

    size_t readable;
    uint8_t *read_ptr = buffer_read_ptr(&proxyData->client_buffer, &readable);
    ssize_t bytesWritten = sendBytesWithMetrics(proxyData->outgoing_fd, read_ptr, readable, 0);
    if (bytesWritten <= 0) {
        if (errno == 0 && bytesWritten == 0) {
            log(ERROR, "[SERVER] Error writing to socket %d: Unknown Error", proxyData->outgoing_fd);
        }
        else if (errno == EWOULDBLOCK || errno == EAGAIN) {
            // log(DEBUG, "Socket %d would block, not writing", proxyData->outgoing_fd);
            // No cambio nada (ni si quiera el interest)
            return;
        }
        log(ERROR, "[SERVER] Error writing to socket %d: %s", proxyData->outgoing_fd, strerror(errno));
        selector_unregister_fd(key->s, proxyData->outgoing_fd);
        proxyData->outgoing_fd = -1;
        return;
    }
    buffer_read_adv(&proxyData->client_buffer, bytesWritten);


    if (buffer_can_read(&proxyData->client_buffer)) {
        selector_set_interest(key->s, proxyData->outgoing_fd, OP_READ | OP_WRITE);
    } else {
        selector_set_interest(key->s, proxyData->outgoing_fd, OP_READ);
    }

    return;
}

void proxy_handler_block(struct selector_key *key) {
    log(DEBUG, "Block Handler called for socket %d", key->fd);
}

void proxy_handler_close(struct selector_key *key) {
    if (key->data == NULL) {
        log(ERROR, "proxy_handler_close called with NULL data. fd=%d", key->fd);
        return;
    }
    log(DEBUG, "Closing proxy connection for proxy %d", key->fd);
    closeSocketWithMetrics(key->fd);
}
