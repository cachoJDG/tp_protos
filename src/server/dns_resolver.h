/* dns_resolver.h */
#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define DNS_CONNECT_TIMEOUT_SEC 5



/**
 * Resolve the given host (IPv4, IPv6 or FQDN) and service/port,
 * then attempt to connect.
 *
 * @param host    Null-terminated string with hostname or numeric IP.
 * @param service Null-terminated string with service name or port number.
//  * @return A connected socket fd (>=0) on success, or -1 on error.
 */
int dns_solve_addr(const char *host, const char *service, struct addrinfo **out_res);



#endif /* DNS_RESOLVER_H */
