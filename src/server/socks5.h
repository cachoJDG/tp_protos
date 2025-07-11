#ifndef SOCKSV5_H_
#define SOCKSV5_H_

#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "./../shared/logger.h"
#include "./../shared/util.h"
#include <stdio.h>
#include "../buffer.h"
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "../selector.h"
#include <signal.h>
#include "../stm.h"
#include <pthread.h>
#include "dns_resolver.h"

void handle_read_passive(struct selector_key *key);

void client_handler_read(struct selector_key *key);
void client_handler_close(struct selector_key *key);
void client_handler_write(struct selector_key *key);
void client_handler_block(struct selector_key *key);

void stm_initial_read_arrival(unsigned state, struct selector_key *key);
StateSocksv5 stm_initial_read(struct selector_key *key);
StateSocksv5 stm_initial_write(struct selector_key *key);

void stm_login_read_arrival(unsigned state, struct selector_key *key);
StateSocksv5 stm_login_read(struct selector_key *key);
StateSocksv5 stm_login_write(struct selector_key *key);

void stm_error(unsigned state, struct selector_key *key);
void stm_done_arrival(unsigned state, struct selector_key *key);

ssize_t recv_ToBuffer_WithMetrics(int fd, buffer *buffer, ssize_t toRead);
ssize_t send_FromBuffer_WithMetrics(int fd, buffer *buffer, ssize_t toWrite);

StateSocksv5 error_redirect(struct selector_key *key);

#endif