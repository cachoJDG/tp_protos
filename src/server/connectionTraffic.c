#include "./connectionTraffic.h"
#include <poll.h>
#include "./../shared/logger.h"
#include "./../shared/util.h"
#include <stdio.h>
#include "../buffer.h"

typedef struct ProxyData {
    int           client_fd;    // descriptor del socket del cliente SOCKS
    int           outgoing_fd; 
    struct addrinfo *connectAddresses;
    struct buffer* client_buffer;  // buffer para almacenar datos del socket del cliente
    struct buffer* outgoing_buffer; // buffer para almacenar datos del socket remoto
    ssize_t bytes;
    // struct state_machine stm;
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
    ClientData *clientData = key->data; // TODO(alex): hacer que esto este separado en las 4 funciones sin usar poll()
    ssize_t received; /////////////////////////////////////////////
    int clientSocket = key->fd;
    int remoteSocket = clientData->outgoing_fd;
    // char receiveBuffer[4096];

    // ------------- NEW -------------
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

    // ------------- OLD -------------

    // Create poll structures to say we are waiting for bytes to read on both sockets.
    // struct pollfd pollFds[2];
    // pollFds[0].fd = clientSocket;
    // pollFds[0].events = POLLIN;
    // pollFds[0].revents = 0;
    // pollFds[1].fd = remoteSocket;
    // pollFds[1].events = POLLIN;
    // pollFds[1].revents = 0;
    
    // What comes in through clientSocket, we send to remoteSocket. What comes in through remoteSocket, we send to clientSocket.
    // This gets repeated until either the client or remote server closes the connection, at which point we close both connections.
    // int alive = 1;
    // do {
    //     int pollResult = poll(pollFds, 2, -1);
    //     if (pollResult < 0) {
    //         log(ERROR, "Poll returned %d: ", pollResult);
    //         perror(NULL);
    //         return;
    //         // return -1;
    //     }

    //     for (int i = 0; i < 2 && alive; i++) {
    //         if (pollFds[i].revents == 0)
    //             continue;

    //         received = recv(pollFds[i].fd, receiveBuffer, sizeof(receiveBuffer), 0);
    //         if (received <= 0) {
    //             alive = 0;
    //         } else {
    //             int otherSocket = pollFds[i].fd == clientSocket ? remoteSocket : clientSocket;
    //             send(otherSocket, receiveBuffer, received, 0);
    //         }
    //     }
    // } while (alive);
}

// Esto no debería hacer nada (de última, debería devolver el mismo estado de antes). Si bien el write podría estar habilitado, no hay nada por escribir
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

// Esto debería enviar datos al servidor
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
        
        return STM_DONE; // or another appropriate terminal state
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

void proxy_handler_read(struct selector_key *key) {
    ProxyData *proxyData = key->data;
    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(proxyData->outgoing_buffer, &available);

    ssize_t bytesRead = recv(key->fd, write_ptr, available, 0);
    if (bytesRead <= 0) {
        log(ERROR, "Error reading from socket %d: %zd", key->fd, bytesRead);
        close(key->fd);
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

void proxy_handler_write(struct selector_key *key) {
    ProxyData *proxyData = key->data;
    size_t readable;
    uint8_t *read_ptr = buffer_read_ptr(proxyData->client_buffer, &readable);
    ssize_t bytesWritten = send(key->fd, read_ptr, readable, 0);
    if (bytesWritten <= 0) {
        log(ERROR, "Error writing to socket %d: %zd", key->fd, bytesWritten);
        close(key->fd);
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
    // Aquí podrías manejar el caso de bloqueo si es necesario
    log(DEBUG, "Block Handler called for socket %d", key->fd);
}

// Hecho con IA
void proxy_handler_close(struct selector_key *key) {
    ProxyData *proxyData = key->data;
    log(INFO, "Closing proxy connection for client %d", proxyData->client_fd);
    // Hacer frees específicos del outgoing_fd

    // Free the ProxyData structure
    free(proxyData);
    
    // Unregister the file descriptor from the selector
    selector_unregister_fd(key->s, key->fd);
}

