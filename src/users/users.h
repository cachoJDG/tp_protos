#ifndef USERS_H
#define USERS_H

#include "../shared/util.h"

#define USER 0                    // Rol de usuario normal
#define ADMIN 1                   // Rol de administrador
#define MAX_USERS_IN_SERVER 216   // Máximo número de usuarios permitidos en el servidor

/**
 * Estructura que representa los datos de un usuario
 */
typedef struct {
    char username[NAME_MAX_LENGTH];  // Nombre de usuario
    char password[NAME_MAX_LENGTH];  // Contraseña del usuario
    char role;                       // Rol del usuario (0 = USER, 1 = ADMIN)
} TUserData;

/**
 * Valida las credenciales de login de un usuario
 * @param username Nombre de usuario a validar
 * @param password Contraseña a validar
 * @return 1 si las credenciales son válidas, 0 en caso contrario
 */
int validate_login(const char *username, const char *password);

/**
 * Añade un nuevo usuario con rol USER al sistema
 * @param username Nombre del usuario a añadir
 * @param password Contraseña del usuario
 * @return 0 en caso de éxito, -1 en caso de error
 */
int add_user(const char *username, const char *password);

/**
 * Carga los usuarios desde el almacenamiento persistente
 * Función para inicializar el sistema de usuarios al arrancar el servidor
 */
void load_users();

/**
 * Busca un usuario en el sistema usando búsqueda binaria
 * @param username Nombre del usuario a buscar
 * @return Índice del usuario en el array si existe, -1 si no se encuentra
 */
int find_user(const char *username);

/**
 * Obtiene una cadena formateada con la lista de todos los usuarios registrados
 * @return Puntero a buffer estático con la lista de usuarios (no liberar)
 */
char *getUsers();

/**
 * Elimina un usuario del sistema
 * @param username Nombre del usuario a eliminar
 * @return 0 en caso de éxito, -1 si el usuario no existe
 */
int remove_user(const char *username);

/**
 * Cambia la contraseña de un usuario existente
 * @param username Nombre del usuario
 * @param newPassword Nueva contraseña a establecer
 * @return 0 en caso de éxito, -1 si el usuario no existe
 */
int change_password(const char *username, const char *newPassword);

/**
 * Cambia el rol de un usuario existente
 * @param username Nombre del usuario
 * @param newRole Nuevo rol a asignar (USER o ADMIN)
 * @return 0 en caso de éxito, -1 si el usuario no existe
 */
int change_role(const char *username, char newRole);

/**
 * Obtiene el rol de un usuario específico
 * @param username Nombre del usuario
 * @return Rol del usuario (USER o ADMIN), -1 si el usuario no existe
 */
char get_user_role(const char *username);

/**
 * Añade un nuevo usuario con rol ADMIN al sistema
 * @param username Nombre del administrador a añadir
 * @param password Contraseña del administrador
 * @return 0 en caso de éxito, -1 en caso de error
 */
int add_admin(const char *username, const char *password);

#endif
