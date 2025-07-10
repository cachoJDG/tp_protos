#ifndef MONITORING_METRICS_H
#define MONITORING_METRICS_H

#include <stddef.h>

typedef struct {
    size_t total_connections;
    size_t current_connections;
    size_t bytes_sent;
    size_t bytes_received;
} MonitoringMetrics;

void metrics_init();

void metrics_increment_connections();

void metrics_decrement_connections();

void metrics_add_bytes_sent(size_t bytes);

void metrics_add_bytes_received(size_t bytes);

MonitoringMetrics *getMetrics();

#endif