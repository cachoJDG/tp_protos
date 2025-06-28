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
    log(DEBUG, "dns_solve_addr: %s:%s resuelto con éxito", host, service);
    return 0;
}


