#ifndef CONNECTION_TRAFFIC_H
#define CONNECTION_TRAFFIC_H
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#include "./../selector.h"

void stm_connection_traffic_arrival(const unsigned state, struct selector_key *key);
unsigned stm_connection_traffic_write(struct selector_key *key);
unsigned stm_connection_traffic_read(struct selector_key *key);
void stm_connection_traffic_departure(const unsigned state, struct selector_key *key);

void proxy_handler_read(struct selector_key *key);
void proxy_handler_write(struct selector_key *key);
void proxy_handler_block(struct selector_key *key);
void proxy_handler_close(struct selector_key *key);

#endif