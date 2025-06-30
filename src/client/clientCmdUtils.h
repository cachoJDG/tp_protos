#ifndef CLIENT_CMD_UTILS_H_
#define CLIENT_CMD_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shared/logger.h"

int sendListUsersCommand(int clientSocket);
int sendAddUserCommand(int clientSocket, char ** commands);
int sendRemoveUserCommand(int clientSocket, char ** commands);
int sendChangePasswordCommand(int clientSocket, char ** commands);

#endif