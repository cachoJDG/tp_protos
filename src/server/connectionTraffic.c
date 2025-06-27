#include "./connectionTraffic.h"
#include <poll.h>
#include "./../shared/logger.h"
#include "./../shared/util.h"
#include <stdio.h>

void stm_connection_traffic_arrival(const unsigned state, struct selector_key *key) {
    ClientData *clientData = key->data; // TODO(alex): hacer que esto este separado en las 4 funciones sin usar poll()
    ssize_t received; /////////////////////////////////////////////
        int clientSocket = key->fd;
        int remoteSocket = clientData->outgoing_fd;
    char receiveBuffer[4096];

    // Create poll structures to say we are waiting for bytes to read on both sockets.
    struct pollfd pollFds[2];
    pollFds[0].fd = clientSocket;
    pollFds[0].events = POLLIN;
    pollFds[0].revents = 0;
    pollFds[1].fd = remoteSocket;
    pollFds[1].events = POLLIN;
    pollFds[1].revents = 0;
    
    // What comes in through clientSocket, we send to remoteSocket. What comes in through remoteSocket, we send to clientSocket.
    // This gets repeated until either the client or remote server closes the connection, at which point we close both connections.
    int alive = 1;
    do {
        int pollResult = poll(pollFds, 2, -1);
        if (pollResult < 0) {
            log(ERROR, "Poll returned %d: ", pollResult);
            perror(NULL);
            return;
            // return -1;
        }

        for (int i = 0; i < 2 && alive; i++) {
            if (pollFds[i].revents == 0)
                continue;

            received = recv(pollFds[i].fd, receiveBuffer, sizeof(receiveBuffer), 0);
            if (received <= 0) {
                alive = 0;
            } else {
                int otherSocket = pollFds[i].fd == clientSocket ? remoteSocket : clientSocket;
                send(otherSocket, receiveBuffer, received, 0);
            }
        }
    } while (alive);


}
unsigned stm_connection_traffic_write(struct selector_key *key) {
    return STM_DONE;
}
unsigned stm_connection_traffic_read(struct selector_key *key) {
    return STM_DONE;
}
void stm_connection_traffic_departure(const unsigned state, struct selector_key *key) {

}

