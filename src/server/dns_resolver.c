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
#include "logger.h"      

int dns_connect(const char *host, const char *service) {
    struct addrinfo hints, *res, *rp;
    int sockfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;    // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;  // TCP

    int err = getaddrinfo(host, service, &hints, &res);
    if (err != 0) {
        log(ERROR, "getaddrinfo(%s, %s) failed: %s",
            host, service, gai_strerror(err));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) {
            log(DEBUG, "socket() failed for %s:%s: %s",
                host, service, strerror(errno));
            continue;
        }

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != 0) { // parte bloqueante
            log(DEBUG, "connect() failed for %s:%s: %s",
                host, service, strerror(errno));
            close(sockfd);
            sockfd = -1;
            continue;
        }

        if (selector_fd_set_nio(sockfd) < 0) { // pasa a un no bloqueante el fd
            log(ERROR, "failed to set non-blocking on socket %d: %s",
                sockfd, strerror(errno));
            
        }

        char addrbuf[INET6_ADDRSTRLEN] = {0};
        getnameinfo(rp->ai_addr, rp->ai_addrlen,
                    addrbuf, sizeof(addrbuf),
                    NULL, 0, NI_NUMERICHOST);
        log(INFO, "Connected to %s:%s [%s]",
            host, service, addrbuf);

        break; 
    }

    freeaddrinfo(res);
    return sockfd;  
}
