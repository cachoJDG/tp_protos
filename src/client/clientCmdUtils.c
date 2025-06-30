#include "clientCmdUtils.h"
#include "monitoring-client.h"

int sendListUsersCommand(int clientSocket) {
    unsigned char msg = LIST_USERS;
    return send(clientSocket, &msg, 1, 0); // SOCKS5 LIST USERS command
}

int sendAddUserCommand(int clientSocket, char ** commands) {
    
    char ans[BUFSIZE] = {0};
    ans[0] = ADD_USER;
    int index = 1;
    int usernameLength = strlen(commands[2]);
    ans[index++] = usernameLength;
    memcpy(ans + index, commands[2], usernameLength);
    index += usernameLength;
    
    int passwordLength = strlen(commands[3]);
    ans[index++] = passwordLength;
    memcpy(ans + index, commands[3], passwordLength);
    index += passwordLength;
    
    return send(clientSocket, ans, index, 0);
}

int sendRemoveUserCommand(int clientSocket, char ** commands) {
    char ans[BUFSIZE] = {0};
    ans[0] = REMOVE_USER;
    
    int index = 1;
    int usernameLength = strlen(commands[2]);
    ans[index++] = usernameLength;
    memcpy(ans + index, commands[2], usernameLength);
    index += usernameLength;
    
    return send(clientSocket, ans, index, 0);
}

int sendChangePasswordCommand(int clientSocket, char ** commands) {
    char ans[BUFSIZE] = {0};
    ans[0] = CHANGE_PASSWORD;
    
    int index = 1;
    int usernameLength = strlen(commands[2]);
    ans[index++] = usernameLength;
    memcpy(ans + index, commands[2], usernameLength);
    index += usernameLength;
    
    int newPasswordLength = strlen(commands[3]);
    ans[index++] = newPasswordLength;
    memcpy(ans + index, commands[3], newPasswordLength);
    index += newPasswordLength;
    
    return send(clientSocket, ans, index, 0);
}