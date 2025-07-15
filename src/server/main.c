#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "../shared/logger.h"
#include "../shared/util.h"
#include "../selector.h"
#include <signal.h>
#include "../stm.h"
#include <pthread.h>
#include "socks5.h"
#include "../users/users.h"
#include "../monitoring/monitoring-server.h"
#include "../monitoring/monitoringMetrics.h"
#include "../args.h"

#define MAXPENDING 32 // Maximum outstanding connection requests
#define SELECTOR_CAPACITY_PROXY 1024

#define ADMIN 1
#define USER 0

static bool keepRunning = true;

/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
int setupTCPServerSocket(char *address, short servicePort) {
	// Construct the server address structure
    char addrBuffer[MAX_ADDR_BUFFER] = {0};
	struct addrinfo addrCriteria;                   // Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;             // Any address family
	addrCriteria.ai_flags = AI_PASSIVE;             // Accept on any address/port
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only stream sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol


    char service[6] = {0}; // max 5 digits + null terminator
    snprintf(service, sizeof(service), "%hu", servicePort);

	struct addrinfo *servAddr; 			// List of server addresses
	int rtnVal = getaddrinfo(address, service, &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		log(FATAL, "getaddrinfo() failed %s", gai_strerror(rtnVal));
		return -1;
	}

	int servSock = -1;
	// Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio, sin especificar una IP en particular
	// Iteramos y hacemos el bind por alguna de ellas, la primera que funcione, ya sea la general para IPv4 (0.0.0.0) o IPv6 (::/0) .
	// Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
	for (struct addrinfo *addr = servAddr; addr != NULL && servSock == -1; addr = addr->ai_next) {
		errno = 0;
		// Create a TCP socket
		servSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (servSock < 0) {
			log(DEBUG, "Cant't create socket on %s : %s ", printAddressPort(addr, addrBuffer), strerror(errno));  
			continue;       // Socket creation failed; try next address
		}
        // man 7 ip. no importa reportar nada si falla. Esto es para permitir reutilizar el address
        setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
		// Bind to ALL the address and set socket to listen
		if ((bind(servSock, addr->ai_addr, addr->ai_addrlen) == 0) && (listen(servSock, MAXPENDING) == 0)) {
			// Print local address of socket
			struct sockaddr_storage localAddr;
			socklen_t addrSize = sizeof(localAddr);
			if (getsockname(servSock, (struct sockaddr *) &localAddr, &addrSize) >= 0) {
				printSocketAddress((struct sockaddr *) &localAddr, addrBuffer);
				log(DEBUG, "Binding to %s", addrBuffer);
			}
		} else {
			log(DEBUG, "Cant't bind %s", strerror(errno));  
			close(servSock);  // Close and try with the next one
			servSock = -1;
		}
	}

	freeaddrinfo(servAddr);

	return servSock;
}

static void sigterm_handler(const int signal) {
    log(DEBUG, "signal %d, cleaning up and exiting", signal);
    keepRunning = false;
}

int main(int argc, char *argv[]) {
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    close(STDIN_FILENO);
    setLogLevel(INFO);

    static struct socks5args args = {0};
    parse_args(argc, argv, &args);

    add_admin(args.users[0].name, args.users[0].pass);

    for(int i = 1; i < args.users_n; i++) {
        add_user(args.users[i].name, args.users[i].pass);
    }
    
    metrics_init();

    int servSock = setupTCPServerSocket(args.socks_addr, args.socks_port);
    if (servSock < 0) return 1;

    int monitoringSock = setupTCPServerSocket(args.mng_addr, args.mng_port);
    if (monitoringSock < 0) {
        close(servSock);
        return 1;
    }

    if (selector_fd_set_nio(servSock) < 0) {
        log(FATAL, "Could not set O_NONBLOCK on listening socket %d", servSock);
        close(servSock);
        close(monitoringSock);
        return 1;
    }

    if (selector_fd_set_nio(monitoringSock) < 0) {
        log(FATAL, "Could not set O_NONBLOCK on monitoring socket %d", monitoringSock);
        close(servSock);
        close(monitoringSock);
        return 1;
    }

    const struct selector_init conf = {
        .signal = SIGALRM,          
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 }
    };
    selector_init(&conf);
    fd_selector selector = selector_new(SELECTOR_CAPACITY_PROXY);

    static const fd_handler listen_handler = {
        .handle_read  = handle_read_passive,
        .handle_write = NULL,
        .handle_block = NULL,
        .handle_close = NULL
    };

    static const fd_handler monitoring_listen_handler = {
        .handle_read  = handle_read_passive_monitoring,
        .handle_write = NULL,
        .handle_block = NULL,
        .handle_close = NULL
    };

    selector_register(selector, servSock, &listen_handler, OP_READ, NULL);
    selector_register(selector, monitoringSock, &monitoring_listen_handler, OP_READ, NULL);

    log(INFO, "SOCKS5 server listening on %s port %u", args.socks_addr, args.socks_port);
    log(INFO, "Monitoring server listening on %s port %u", args.mng_addr, args.mng_port);
    selector_status sel_status = SELECTOR_SUCCESS;
    while (keepRunning && (sel_status = selector_select(selector)) == SELECTOR_SUCCESS) {
        ; 
    }
    log(INFO, "closing server with selector status=%s", selector_error(sel_status));
    selector_destroy(selector);
    selector_close();
    if(servSock >= 0) {
        close(servSock);
    }

    if(monitoringSock >= 0) {
        close(monitoringSock);
    }
    return 0;
}
