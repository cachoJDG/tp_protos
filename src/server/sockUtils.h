#ifndef SOCKSV5_UTILS_H_
#define SOCKSV5_UTILS_H_

#include <stddef.h>
#include <sys/socket.h>

/**
 * Envía datos a través de un socket y actualiza las métricas de bytes enviados
 * @param fd Descriptor del socket
 * @param buf Buffer con los datos a enviar
 * @param len Número de bytes a enviar
 * @param flags Flags para la función send (se añade automáticamente MSG_NOSIGNAL)
 * @return Número de bytes enviados en caso de éxito, -1 en caso de error
 */
ssize_t sendBytesWithMetrics(int fd, const void *buf, size_t len, int flags);

/**
 * Recibe datos de un socket y actualiza las métricas de bytes recibidos
 * @param fd Descriptor del socket
 * @param buf Buffer donde almacenar los datos recibidos
 * @param len Número máximo de bytes a recibir
 * @param flags Flags para la función recv
 * @return Número de bytes recibidos en caso de éxito, -1 en caso de error
 */
ssize_t recvBytesWithMetrics(int fd, void *buf, size_t len, int flags);

/**
 * Cierra un socket y actualiza las métricas de conexiones activas
 * @param fd Descriptor del socket a cerrar
 * @return 0 en caso de éxito, -1 en caso de error
 */
int closeSocketWithMetrics(int fd);

#endif
