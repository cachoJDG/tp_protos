#ifndef CLIENT_CMD_PARSER_H_
#define CLIENT_CMD_PARSER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shared/logger.h"

/**
 * Parsea el comando LIST USERS
 * @param commands Array de strings con los comandos
 * @param commandCount Número de comandos en el array
 * @return 1 si el comando es válido (LIST USERS), 0 en caso contrario
 */
int parseListUsersCommand(char ** commands, size_t commandCount);

/**
 * Parsea el comando ADD USER
 * @param commands Array de strings con los comandos (debe contener: ADD USER <username> <password>)
 * @param commandCount Número de comandos en el array (debe ser 4)
 * @return 1 si el comando es válido, 0 en caso contrario
 */
int parseAddUserCommand(char ** commands, size_t commandCount);

/**
 * Parsea el comando REMOVE USER
 * @param commands Array de strings con los comandos (debe contener: REMOVE USER <username>)
 * @param commandCount Número de comandos en el array (debe ser 3)
 * @return 1 si el comando es válido, 0 en caso contrario
 */
int parseRemoveUserCommand(char ** commands, size_t commandCount);

/**
 * Parsea el comando CHANGE PASSWORD
 * @param commands Array de strings con los comandos (debe contener: CHANGE PASSWORD <username> <newpassword>)
 * @param commandCount Número de comandos en el array (debe ser 4)
 * @return 1 si el comando es válido, 0 en caso contrario
 */
int parseChangePasswordCommand(char ** commands, size_t commandCount);

/**
 * Parsea el comando GET METRICS
 * @param commands Array de strings con los comandos
 * @param commandCount Número de comandos en el array (debe ser 2)
 * @return 1 si el comando es válido (GET METRICS), 0 en caso contrario
 */
int parseGetMetricsCommand(char ** commands, size_t commandCount);

/**
 * Parsea el comando CHANGE ROLE
 * @param commands Array de strings con los comandos (debe contener: CHANGE ROLE <username> <role>)
 * @param commandCount Número de comandos en el array (debe ser 4)
 * @return 1 si el comando es válido, 0 en caso contrario
 */
int parseChangeRoleCommand(char ** commands, size_t commandCount);

#endif
