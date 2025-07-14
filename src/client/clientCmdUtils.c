
#include "clientCmdUtils.h"
#include "monitoring-client.h"

int sendListUsersCommand(int clientSocket) {
    unsigned char msg = LIST_USERS;
    return send(clientSocket, &msg, 1, 0);
}

int sendAddUserCommand(int clientSocket, char **commands) {
    char ans[BUFSIZE_MONITORING] = {0};
    ans[0] = ADD_USER;
    int index = 1;

    int usernameLength = strlen(commands[2]);
    int passwordLength = strlen(commands[3]);

    if (usernameLength < 1 || usernameLength > UNAME_MAX_LENGTH) {
        fprintf(stderr, "Client error: username length is invalid\n");
        return -1;
    }
    if (passwordLength < 1 || passwordLength > PASSWORD_MAX_LENGTH) {
        fprintf(stderr, "Client error: password length is invalid\n");
        return -1;
    }

    ans[index++] = usernameLength;
    memcpy(ans + index, commands[2], usernameLength);
    index += usernameLength;

    ans[index++] = passwordLength;
    memcpy(ans + index, commands[3], passwordLength);
    index += passwordLength;

    return send(clientSocket, ans, index, 0);
}

int sendRemoveUserCommand(int clientSocket, char **commands) {
    char ans[BUFSIZE_MONITORING] = {0};
    ans[0] = REMOVE_USER;
    int index = 1;

    int usernameLength = strlen(commands[2]);
    if (usernameLength < 1 || usernameLength > UNAME_MAX_LENGTH) {
        fprintf(stderr, "Client error: username length is invalid\n");
        return -1;
    }

    ans[index++] = usernameLength;
    memcpy(ans + index, commands[2], usernameLength);
    index += usernameLength;

    return send(clientSocket, ans, index, 0);
}

int sendChangePasswordCommand(int clientSocket, char **commands) {
    char ans[BUFSIZE_MONITORING] = {0};
    ans[0] = CHANGE_PASSWORD;
    int index = 1;

    int usernameLength = strlen(commands[2]);
    int newPasswordLength = strlen(commands[3]);

    if (usernameLength < 1 || usernameLength > UNAME_MAX_LENGTH) {
        fprintf(stderr, "Client error: username length is invalid\n");
        return -1;
    }
    if (newPasswordLength < 1 || newPasswordLength > PASSWORD_MAX_LENGTH) {
        fprintf(stderr, "Client error: password length is invalid\n");
        return -1;
    }

    ans[index++] = usernameLength;
    memcpy(ans + index, commands[2], usernameLength);
    index += usernameLength;

    ans[index++] = newPasswordLength;
    memcpy(ans + index, commands[3], newPasswordLength);
    index += newPasswordLength;

    return send(clientSocket, ans, index, 0);
}

int sendGetMetricsCommand(int clientSocket) {
    unsigned char msg = GET_METRICS;
    return send(clientSocket, &msg, 1, 0);
}

int sendChangeRoleCommand(int clientSocket, char **commands) {
    char ans[BUFSIZE_MONITORING] = {0};
    ans[0] = CHANGE_ROLE;
    int index = 1;

    if((commands[3][0] != '0' && commands[3][0] != '1') || strlen(commands[3]) != 1) {
        fprintf(stderr, "Client error: role must be '1' (admin) or '0' (user)\n");
        return -1;
    }

    int usernameLength = strlen(commands[2]);
    if (usernameLength < 1 || usernameLength > UNAME_MAX_LENGTH) {
        fprintf(stderr, "Client error: username length is invalid\n");
        return -1;
    }

    ans[index++] = usernameLength;
    memcpy(ans + index, commands[2], usernameLength);
    index += usernameLength;
    ans[index++] = commands[3][0] - '0'; // Convert '0'/'1' to 0/1

    return send(clientSocket, ans, index, 0);
}
