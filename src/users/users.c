#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FILENAME "src/users/users.csv"
//#define FILENAME "users.csv"

typedef struct {
    char username[50];
    char password[50];
} TUserData;

TUserData users[216];
int user_count = 0;

// Comparador para qsort
int user_cmp(const void *a, const void *b) {
    const TUserData *ua = (const TUserData *)a;
    const TUserData *ub = (const TUserData *)b;
    return strcmp(ua->username, ub->username);
}

// Cargar usuarios desde el archivo CSV
void load_users() {
    FILE *f = fopen(FILENAME, "r");
    if (!f) {
        perror("No se pudo abrir el archivo de usuarios");
        return;
    }
    char line[128];
    while (fgets(line, sizeof(line), f) && user_count < 216) {
        char *username = strtok(line, ";");
        char *password = strtok(NULL, ";");
        if (username && password) {
            strncpy(users[user_count].username, username, sizeof(users[user_count].username) - 1);
            users[user_count].username[sizeof(users[user_count].username) - 1] = '\0';
            strncpy(users[user_count].password, password, sizeof(users[user_count].password) - 1);
            users[user_count].password[sizeof(users[user_count].password) - 1] = '\0';
            user_count++;
        }
    }
    fclose(f);
    qsort(users, user_count, sizeof(TUserData), user_cmp);
}

int find_user(const char *username) {
    int left = 0, right = user_count - 1;
    while (left <= right) {
        int mid = (left + right) / 2;
        int cmp = strcmp(username, users[mid].username);
        if (cmp == 0) return mid;
        if (cmp < 0) right = mid - 1;
        else left = mid + 1;
    }
    return -1;
}

int validate_login(const char *username, const char *password) {
    int idx = find_user(username);
    return (idx >= 0 && strcmp(users[idx].password, password) == 0);
}

int add_user(const char *username, const char *password) {
    if (user_count >= 216) {
        fprintf(stderr, "No se pueden agregar más usuarios.\n");
        return -1;
    }
    if (find_user(username) >= 0) {
        fprintf(stderr, "El usuario ya existe.\n");
        return -1;
    }
    strncpy(users[user_count].username, username, sizeof(users[user_count].username) - 1);
    users[user_count].username[sizeof(users[user_count].username) - 1] = '\0';
    strncpy(users[user_count].password, password, sizeof(users[user_count].password) - 1);
    users[user_count].password[sizeof(users[user_count].password) - 1] = '\0';
    user_count++;
    qsort(users, user_count, sizeof(TUserData), user_cmp);
    return 0;
}

void print_users() {
    for (int i = 0; i < user_count; i++) {
        printf("Usuario: %s, Contraseña: %s\n", users[i].username, users[i].password);
    }
}

char *getUsers(){
    static char buffer[1024];
    buffer[0] = '\0'; // Inicializar el buffer
    strcat(buffer, "Usuarios registrados:\n");
    for (int i = 0; i < user_count; i++) {
        strcat(buffer, users[i].username);
        strcat(buffer, "\n");
    }
    strcat(buffer, "\0"); // Asegurar que el buffer esté null-terminated
    return buffer;
}

int remove_user(const char *username) {
    int idx = find_user(username);
    if (idx < 0) {
        fprintf(stderr, "El usuario no existe.\n");
        return -1;
    }
    for (int i = idx; i < user_count - 1; i++) {
        users[i] = users[i + 1];
    }
    user_count--;
    return 0;
}

int change_password(const char *username, const char *newPassword) {
    int idx = find_user(username);
    if (idx < 0) {
        fprintf(stderr, "El usuario no existe.\n");
        return -1;
    }
    strncpy(users[idx].password, newPassword, sizeof(users[idx].password) - 1);
    users[idx].password[sizeof(users[idx].password) - 1] = '\0';
    return 0;
}