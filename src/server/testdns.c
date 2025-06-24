/* concurrent_dns_test.c */
#define _POSIX_C_SOURCE 200112L    /* para getaddrinfo/getnameinfo */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include "dns_resolver.h"

#define POOL_SIZE 3
#define MAX_JOBS  16

typedef struct {
    const char *host;
    const char *service;
} dns_job_t;

/* Cola simple de trabajos */
static dns_job_t job_queue[MAX_JOBS];
static int       job_head = 0, job_tail = 0;
static int       jobs_pending = 0;
static int       stop_pool = 0;

static pthread_mutex_t queue_mtx  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  queue_cnd  = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  done_cnd   = PTHREAD_COND_INITIALIZER;

/* Aquí guardamos los FDs para cerrarlos al final */
static int result_fds[MAX_JOBS];
static int result_count = 0;
static pthread_mutex_t result_mtx = PTHREAD_MUTEX_INITIALIZER;

// Saca un trabajo de la cola; devuelve 0 si lo hizo, -1 si no quedan
static int pop_job(dns_job_t *out) {
    pthread_mutex_lock(&queue_mtx);
    while (jobs_pending == 0 && !stop_pool) {
        pthread_cond_wait(&queue_cnd, &queue_mtx);
    }
    if (jobs_pending == 0 && stop_pool) {
        pthread_mutex_unlock(&queue_mtx);
        return -1;
    }
    *out = job_queue[job_head];
    job_head = (job_head + 1) % MAX_JOBS;
    jobs_pending--;
    pthread_cond_signal(&done_cnd);
    pthread_mutex_unlock(&queue_mtx);
    return 0;
}

// Inserta un trabajo en la cola; asume que no se desborda MAX_JOBS
static void push_job(const char *host, const char *service) {
    pthread_mutex_lock(&queue_mtx);
    job_queue[job_tail] = (dns_job_t){ .host = host, .service = service };
    job_tail = (job_tail + 1) % MAX_JOBS;
    jobs_pending++;
    pthread_cond_signal(&queue_cnd);
    pthread_mutex_unlock(&queue_mtx);
}

// Función que corre cada hilo del pool
static void *worker(void *arg) {
    (void)arg;
    dns_job_t job;
    while (pop_job(&job) == 0) {
        int fd = dns_connect(job.host, job.service);
        if (fd >= 0) {
            printf("[THREAD %lu] Connected to %s:%s (fd=%d)\n",
                   (unsigned long)pthread_self(),
                   job.host, job.service, fd);
            // guardo el fd en result_fds, sin cerrarlo aún
            pthread_mutex_lock(&result_mtx);
            result_fds[result_count++] = fd;
            pthread_mutex_unlock(&result_mtx);
        } else {
            printf("[THREAD %lu] Failed to connect to %s:%s\n",
                   (unsigned long)pthread_self(),
                   job.host, job.service);
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Uso: %s <host1> <port1> <host2> <port2>\n", argv[0]);
        return 1;
    }

    // 1) Arranca el pool de POOL_SIZE hilos
    pthread_t pool[POOL_SIZE];
    for (int i = 0; i < POOL_SIZE; i++) {
        if (pthread_create(&pool[i], NULL, worker, NULL) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    // 2) Encola los 2 trabajos
    push_job(argv[1], argv[2]);
    push_job(argv[3], argv[4]);

    // 3) Espera a que todos los trabajos pendientes terminen
    pthread_mutex_lock(&queue_mtx);
    while (jobs_pending > 0) {
        pthread_cond_wait(&done_cnd, &queue_mtx);
    }
    // 4) Señaliza a los hilos que terminen
    stop_pool = 1;
    pthread_cond_broadcast(&queue_cnd);
    pthread_mutex_unlock(&queue_mtx);

    // 5) Espera a que todos los hilos mueran
    for (int i = 0; i < POOL_SIZE; i++) {
        pthread_join(pool[i], NULL);
    }

    printf("Cerrando %d sockets:\n", result_count);
    for (int i = 0; i < result_count; i++) {
        printf("  closing fd %d\n", result_fds[i]);
        close(result_fds[i]);
    }

    return 0;

}