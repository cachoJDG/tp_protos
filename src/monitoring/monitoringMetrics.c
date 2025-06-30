#include "monitoringMetrics.h"
#include <string.h>

void metrics_init() {
    memset(&metrics, 0, sizeof(MonitoringMetrics));
}

void metrics_increment_connections() {
    metrics.total_connections++;
    metrics.current_connections++;
}

void metrics_decrement_connections() {
    if (metrics.current_connections > 0) {
        metrics.current_connections--;
    }
}

void metrics_add_bytes_sent(size_t bytes) {
    metrics.bytes_sent += bytes;
}

void metrics_add_bytes_received(size_t bytes) {
    metrics.bytes_received += bytes;
}

MonitoringMetrics *getMetrics() {
    return &metrics;
}