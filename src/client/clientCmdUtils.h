#ifndef CLIENT_CMD_UTILS_H_
#define CLIENT_CMD_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shared/logger.h"
#include <sys/types.h>
#include <sys/socket.h>

/**
 * Envía el comando LIST USERS al servidor de monitoreo
 * @param clientSocket Socket del cliente conectado al servidor
 * @return Número de bytes enviados en caso de éxito, -1 en caso de error
 */
int sendListUsersCommand(int clientSocket);

/**
 * Envía el comando ADD USER al servidor de monitoreo
 * @param clientSocket Socket del cliente conectado al servidor
 * @param commands Array de comandos que debe contener username y password en posiciones [2] y [3]
 * @return Número de bytes enviados en caso de éxito, -1 en caso de error
 */
int sendAddUserCommand(int clientSocket, char ** commands);

/**
 * Envía el comando REMOVE USER al servidor de monitoreo
 * @param clientSocket Socket del cliente conectado al servidor
 * @param commands Array de comandos que debe contener username en posición [2]
 * @return Número de bytes enviados en caso de éxito, -1 en caso de error
 */
int sendRemoveUserCommand(int clientSocket, char ** commands);

/**
 * Envía el comando CHANGE PASSWORD al servidor de monitoreo
 * @param clientSocket Socket del cliente conectado al servidor
 * @param commands Array de comandos que debe contener username y nueva password en posiciones [2] y [3]
 * @return Número de bytes enviados en caso de éxito, -1 en caso de error
 */
int sendChangePasswordCommand(int clientSocket, char ** commands);

/**
 * Envía el comando GET METRICS al servidor de monitoreo
 * @param clientSocket Socket del cliente conectado al servidor
 * @return Número de bytes enviados en caso de éxito, -1 en caso de error
 */
int sendGetMetricsCommand(int clientSocket);

/**
 * Envía el comando CHANGE ROLE al servidor de monitoreo
 * @param clientSocket Socket del cliente conectado al servidor
 * @param commands Array de comandos que debe contener username y rol en posiciones [2] y [3]
 * @return Número de bytes enviados en caso de éxito, -1 en caso de error
 */
int sendChangeRoleCommand(int clientSocket, char ** commands);

#endif
