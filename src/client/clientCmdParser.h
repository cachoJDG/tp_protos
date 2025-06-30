#ifndef CLIENT_CMD_PARSER_H_
#define CLIENT_CMD_PARSER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shared/logger.h"

int parseListUsersCommand(char ** commands, size_t commandCount);
int parseAddUserCommand(char ** commands, size_t commandCount);
int parseRemoveUserCommand(char ** commands, size_t commandCount);
int parseChangePasswordCommand(char ** commands, size_t commandCount);

#endif