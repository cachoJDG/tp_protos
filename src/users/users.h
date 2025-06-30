
int validate_login(const char *username, const char *password);
int add_user(const char *username, const char *password);
void load_users();
int find_user(const char *username);
char *getUsers();
int remove_user(const char *username);