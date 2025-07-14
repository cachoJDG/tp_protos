#ifndef USERS_H
#define USERS_H

#include "../shared/util.h"

#define USER 0
#define ADMIN 1
#define MAX_USERS_IN_SERVER 216

typedef struct {
    char username[NAME_MAX_LENGTH];
    char password[NAME_MAX_LENGTH];
    char role; // 0 for user, 1 for admin
} TUserData;

int validate_login(const char *username, const char *password);
int add_user(const char *username, const char *password);
void load_users();
int find_user(const char *username);
char *getUsers();
int remove_user(const char *username);
int change_password(const char *username, const char *newPassword);
int change_role(const char *username, char newRole);
char get_user_role(const char *username);
int add_admin(const char *username, const char *password);

#endif