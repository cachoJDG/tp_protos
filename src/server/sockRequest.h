#ifndef SOCK_REQUEST_H
#define SOCK_REQUEST_H
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

#include "./../selector.h"

void stm_request_read_arrival(unsigned state, struct selector_key *key);
StateSocksv5 stm_request_read(struct selector_key *key);
StateSocksv5 beginConnection(struct selector_key *key);
StateSocksv5 stm_request_write(struct selector_key *key);
StateSocksv5 stm_dns_done(struct selector_key *key);
void stm_connect_attempt_arrival(unsigned state, struct selector_key *key);
StateSocksv5 stm_connect_attempt_write(struct selector_key *key);

#endif