#ifndef SOCKSV5_UTILS_H_
#define SOCKSV5_UTILS_H_

#include <stddef.h>
#include <sys/socket.h>

ssize_t sendBytesWithMetrics(int fd, const void *buf, size_t len, int flags);

ssize_t recvBytesWithMetrics(int fd, void *buf, size_t len, int flags);

int closeSocketWithMetrics(int fd);

#endif