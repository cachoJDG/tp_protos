#include "sockUtils.h"
#include <stdio.h>
#include <unistd.h>
#include "../monitoring/monitoringMetrics.h"
#include <sys/types.h>
#include <sys/socket.h>

size_t sendBytesWithMetrics(int fd, const void *buf, size_t len, int flags) {
    size_t bytesSent = send(fd, buf, len, flags);
    if (bytesSent > 0) {
        metrics_add_bytes_sent(bytesSent);
    }
    return bytesSent;
}

size_t recvBytesWithMetrics(int fd, void *buf, size_t len, int flags) {
    size_t bytesReceived = recv(fd, buf, len, flags);
    if (bytesReceived > 0) {
        metrics_add_bytes_received(bytesReceived);
    }
    return bytesReceived;
}

int closeSocketWithMetrics(int fd) {
    int response = close(fd);
    if(fd >= 0 && response == 0) {
        metrics_decrement_connections();
    }
    return response;
}