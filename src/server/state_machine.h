#ifndef BASIC_STATE_MACHINE_H
#define BASIC_STATE_MACHINE_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "../shared/logger.h"
#include "../shared/util.h"
#include "../selector.h"
#include "../parser.h"

void stm_initial_read_arrival(unsigned state, struct selector_key *key);

StateSocksv5 stm_initial_read_version(struct selector_key *key);
StateSocksv5 stm_initial_read_method_count(struct selector_key *key);
StateSocksv5 stm_initial_read_methods(struct selector_key *key);

StateSocksv5 stm_initial_write(struct selector_key *key);

void stm_login_read_arrival(unsigned state, struct selector_key *key);

StateSocksv5 stm_login_read_version(struct selector_key *key);
StateSocksv5 stm_login_read_user_count(struct selector_key *key);
StateSocksv5 stm_login_read_user(struct selector_key *key);
StateSocksv5 stm_login_read_pass_count(struct selector_key *key);
StateSocksv5 stm_login_read_pass(struct selector_key *key);

StateSocksv5 stm_login_write(struct selector_key *key);

void stm_request_read_arrival(unsigned state, struct selector_key *key);

StateSocksv5 stm_request_read_version(struct selector_key *key);
StateSocksv5 stm_request_read_cmd(struct selector_key *key);
StateSocksv5 stm_request_read_reserved(struct selector_key *key);
StateSocksv5 stm_request_read_atyp(struct selector_key *key);
StateSocksv5 stm_request_read_ipv4(struct selector_key *key);
StateSocksv5 stm_request_read_domain_name_size(struct selector_key *key);
StateSocksv5 stm_request_read_domain_name(struct selector_key *key);
StateSocksv5 stm_request_read_ipv6(struct selector_key *key);
StateSocksv5 stm_request_read_port(struct selector_key *key);

StateSocksv5 stm_request_write(struct selector_key *key);

StateSocksv5 stm_dns_done(struct selector_key *key);

void stm_error(unsigned state, struct selector_key *key);

void stm_done_arrival(unsigned state, struct selector_key *key);

#endif // BASIC_STATE_MACHINE_H