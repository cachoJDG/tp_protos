#include "clientCmdUtils.h"
#include "monitoring-client.h"

int sendListUsersCommand(int clientSocket) {
    unsigned char msg = LIST_USERS;
    return send(clientSocket, &msg, 1, 0); // SOCKS5 LIST USERS command
}

int sendAddUserCommand(int clientSocket, char ** commands) {
    
    char ans[BUFSIZE_MONITORING] = {0};
    ans[0] = ADD_USER;
    int index = 1;
    int usernameLength = strlen(commands[2]);
    int passwordLength = strlen(commands[3]);

    if(usernameLength < 1 || usernameLength > UNAME_MAX_LENGTH) {
        fprintf(stderr, "Client error: username length is invalid\n");
        return -1;
    }

    if(passwordLength < 1 || passwordLength > PASSWORD_MAX_LENGTH) {
        fprintf(stderr, "Client error: password length is invalid\n");
        return -1;
    }

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
    char ans[BUFSIZE_MONITORING] = {0};
    ans[0] = REMOVE_USER;
    
    int index = 1;
    int usernameLength = strlen(commands[2]);
    if(usernameLength < 1 || usernameLength > UNAME_MAX_LENGTH) {
        fprintf(stderr, "Client error: username length is invalid\n");
        return -1;
    }
    ans[index++] = usernameLength;
    memcpy(ans + index, commands[2], usernameLength);
    index += usernameLength;
    
    return send(clientSocket, ans, index, 0);
}

int sendChangePasswordCommand(int clientSocket, char ** commands) {
    char ans[BUFSIZE_MONITORING] = {0};
    ans[0] = CHANGE_PASSWORD;
    
    int index = 1;
    int usernameLength = strlen(commands[2]);
    int newPasswordLength = strlen(commands[3]);

    if(usernameLength < 1 || usernameLength > UNAME_MAX_LENGTH) {
        fprintf(stderr, "Client error: username length is invalid\n");
        return -1;
    }

    if(newPasswordLength < 1 || newPasswordLength > PASSWORD_MAX_LENGTH) {
        fprintf(stderr, "Client error: password length is invalid\n");
        return -1;
    }

    ans[index++] = usernameLength;
    memcpy(ans + index, commands[2], usernameLength);
    index += usernameLength;
    
    int newPasswordLength = strlen(commands[3]);
    ans[index++] = newPasswordLength;
    memcpy(ans + index, commands[3], newPasswordLength);
    index += newPasswordLength;
    
    return send(clientSocket, ans, index, 0);
}

int sendGetMetricsCommand(int clientSocket) {
    unsigned char msg = GET_METRICS;
    return send(clientSocket, &msg, 1, 0);
}