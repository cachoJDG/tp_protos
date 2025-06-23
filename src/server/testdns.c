// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <string.h>
// #include <errno.h>
// #include <signal.h>               
// #include <sys/socket.h>
// #include "dns_resolver.h"
// #include "../selector.h"         

// static void handle_write(struct selector_key *key) {
//     int fd = key->fd;
//     int so_err = 0;
//     socklen_t len = sizeof(so_err);
//     if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len) < 0 || so_err != 0) {
//         printf("[SELECTOR] Connection failed on fd %d: %s\n",
//                fd, so_err ? strerror(so_err) : strerror(errno));
//     } else {
//         printf("[SELECTOR] Connected successfully on fd %d\n", fd);
//     }
//     selector_unregister_fd(key->s, fd); 
//     close(fd);
// }

// int main(int argc, char *argv[]) {
//     if (argc != 5) {
//         fprintf(stderr, "Uso: %s <host1> <port1> <host2> <port2>\n", argv[0]);
//         return 1;
//     }

//     struct selector_init conf = {
//         .signal         = SIGALRM,        
//         .select_timeout = { .tv_sec = 1, .tv_nsec = 0 }
//     };
//     if (selector_init(&conf) != SELECTOR_SUCCESS) {
//         fprintf(stderr, "selector_init: %s\n",
//                 selector_error(selector_init(&conf)));
//         return 1;
//     }

//     fd_selector sel = selector_new(2);
//     if (!sel) {
//         fprintf(stderr, "selector_new failed\n");
//         return 1;
//     }

//     for (int i = 0; i < 2; i++) {
//         const char *host = argv[1 + i*2];
//         const char *port = argv[2 + i*2];
//         int fd = dns_connect(host, port);
//         if (fd < 0) {
//             printf("[MAIN] dns_connect failed for %s:%s\n", host, port);
//             continue;
//         }
//         struct fd_handler h = {
//             .handle_read  = NULL,
//             .handle_write = handle_write,
//             .handle_block = NULL,
//             .handle_close = NULL
//         };
//         if (selector_register(sel, fd, &h, OP_WRITE, NULL) != SELECTOR_SUCCESS) {
//             perror("selector_register");
//             close(fd);
//         }
//     }

//     while (selector_select(sel) == SELECTOR_SUCCESS) {
//     }

//     selector_destroy(sel);
//     selector_close();
//     return 0;
// }
