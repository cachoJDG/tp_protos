/* dns_resolver.c */
#include "dns_resolver.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>    // INET6_ADDRSTRLEN
#include <fcntl.h>        
#include "../selector.h"  
#include "../shared/logger.h"      


int dns_solve_addr(const char *host, const char *service, struct addrinfo **out_res) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;    // IPv4 o IPv6
    hints.ai_socktype = SOCK_STREAM;  // uso TCP (solo para seleccionar tipo de servicio)

    err = getaddrinfo(host, service, &hints, &res);
    if (err != 0) {
        log(ERROR, "getaddrinfo(%s, %s) failed: %s",
            host, service, gai_strerror(err));
        return -1;
    }

    // Devuelvo al llamador la lista de addrinfo
    *out_res = res;
    // log(DEBUG, "dns_solve_addr: %s:%s resuelto con éxito", host, service);
    return 0;
}

void *dns_thread_func(void *arg) {
    DnsJob *job = (DnsJob *)arg;
    if (dns_solve_addr(job->host, job->service, job->result) == 0) {
        struct addrinfo *p;
        char ipstr[INET6_ADDRSTRLEN];

        for (p = *job->result; p != NULL; p = p->ai_next) {
            void *addr;
            if (p->ai_family == AF_INET) {
                addr = &((struct sockaddr_in *)p->ai_addr)->sin_addr;
            } else {  // AF_INET6
                addr = &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr;
            }
            inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
            log(DEBUG, "DNS resuelto para %s:%s -> %s", job->host, job->service, ipstr);
        }

    } else {
        log(DEBUG, "Error al resolver DNS para %s:%s", job->host, job->service);
        job->result = NULL;
    }
    selector_notify_block(job->selector, job->client_fd);
    free(job);
    return NULL;
}


