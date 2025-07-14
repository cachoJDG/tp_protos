#ifndef MONITORING_METRICS_H
#define MONITORING_METRICS_H

#include <stddef.h>

/**
 * Estructura que almacena las métricas del servidor de monitoreo
 */
typedef struct {
    size_t total_connections;    // Total de conexiones realizadas desde el inicio
    size_t current_connections;  // Conexiones activas actuales
    size_t bytes_sent;          // Total de bytes enviados
    size_t bytes_received;      // Total de bytes recibidos
} MonitoringMetrics;

/**
 * Inicializa la estructura de métricas, poniendo todos los valores en 0
 */
void metrics_init();

/**
 * Incrementa el contador de conexiones totales y actuales
 * Se llama cuando se establece una nueva conexión
 */
void metrics_increment_connections();

/**
 * Decrementa el contador de conexiones actuales
 * Se llama cuando se cierra una conexión existente
 */
void metrics_decrement_connections();

/**
 * Añade bytes al contador de bytes enviados
 * @param bytes Número de bytes enviados a agregar al total
 */
void metrics_add_bytes_sent(size_t bytes);

/**
 * Añade bytes al contador de bytes recibidos
 * @param bytes Número de bytes recibidos a agregar al total
 */
void metrics_add_bytes_received(size_t bytes);

/**
 * Obtiene un puntero a la estructura de métricas global
 * @return Puntero a la estructura MonitoringMetrics con las métricas actuales
 */
MonitoringMetrics *getMetrics();

#endif