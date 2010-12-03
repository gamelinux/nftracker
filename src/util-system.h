#ifndef UTIL_SYSTEM_H
#define UTIL_SYSTEM_H
void check_interrupt();
int set_chroot(void);
int drop_privs(void);
int is_valid_path(const char *path);
int create_pid_file(const char *path, const char *filename);
int daemonize();
#endif // UTIL_SYSTEM_H
