#include "clientCmdParser.h"

int parseListUsersCommand(char ** commands, size_t commandCount){
    if(commands == NULL || commandCount != 2) {
        log(ERROR, "Wrong command format for LIST USERS");
        return 0;
    }
    return (strcmp(commands[0], "LIST") == 0 && strcmp(commands[1], "USERS") == 0);
}

int parseAddUserCommand(char ** commands, size_t commandCount){
    if(commands == NULL || commandCount != 4) {
        log(ERROR, "Wrong command format for ADD USER <username> <password>");
        return 0;
    }
    return (strcmp(commands[0], "ADD") == 0 && strcmp(commands[1], "USER") == 0);
}

int parseRemoveUserCommand(char ** commands, size_t commandCount){
    if(commands == NULL || commandCount != 3) {
        log(ERROR, "Wrong command format for REMOVE USER <username>");
        return 0;
    }
    return (strcmp(commands[0], "REMOVE") == 0 && strcmp(commands[1], "USER") == 0);
}

int parseChangePasswordCommand(char ** commands, size_t commandCount){
    if(commands == NULL || commandCount != 4) {
        log(ERROR, "Wrong command format for CHANGE PASSWORD <username> <new_password>");
        return 0;
    }
    return (strcmp(commands[0], "CHANGE") == 0 && strcmp(commands[1], "PASSWORD") == 0);
}