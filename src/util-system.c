#include "common.h"
#include "config.h"
#include "nftracker.h"
#include "util-log.h"
#include "util-system.h"

/*  G L O B A L E S  *********************************************************/
extern globalconfig config;

void check_interrupt()
{
    if (ISSET_CONFIG_INTR(config) == 1) {
//        game_over();
//   } else if (intr_flag == 2) {
//        update_asset_list();
//    } else if (intr_flag == 3) {
//        set_end_sessions();
//    } else {
//        intr_flag = 0;
    }
}

int set_chroot(void)
{
    char *absdir;
    //char *logdir;
    int abslen;

    /*
     * logdir = get_abs_path(logpath); 
     */

    /*
     * change to the directory 
     */
    if (chdir(config.chroot_dir) != 0) {
        elog("set_chroot: Can not chdir to \"%s\": %s\n", config.chroot_dir,
               strerror(errno));
    }

    /*
     * always returns an absolute pathname 
     */
    absdir = getcwd(NULL, 0);
    abslen = strlen(absdir);

    /*
     * make the chroot call 
     */
    if (chroot(absdir) < 0) {
        elog("Can not chroot to \"%s\": absolute: %s: %s\n", config.chroot_dir,
               absdir, strerror(errno));
        exit(3);
    }

    if (chdir("/") < 0) {
        elog("Can not chdir to \"/\" after chroot: %s\n",
               strerror(errno));
        exit(3);
    }

    return 0;
}

int drop_privs(void)
{
    struct group *gr;
    struct passwd *pw;
    char *endptr;
    int i;
    int do_setuid = 0;
    int do_setgid = 0;
    unsigned long groupid = 0;
    unsigned long userid = 0;

    if (config.group_name != NULL) {
        do_setgid = 1;
        if (!isdigit(config.group_name[0])) {
            gr = getgrnam(config.group_name);
            if(!gr){
                if(config.chroot_dir){
                    elog("ERROR: you have chrootetd and must set numeric group ID.\n");
                    exit(1);
                }else{
                    elog("ERROR: couldn't get ID for group %s, group does not exist.\n", config.group_name);
                    exit(1);
                }
            }
            groupid = gr->gr_gid;
        } else {
            groupid = strtoul(config.group_name, &endptr, 10);
        }
    }

    if (config.user_name != NULL) {
        do_setuid = 1;
        do_setgid = 1;
        if (isdigit(config.user_name[0]) == 0) {
            pw = getpwnam(config.user_name);
            if (pw != NULL) {
                userid = pw->pw_uid;
            } else {
                printf("[E] User %s not found!\n", config.user_name);
            }
        } else {
            userid = strtoul(config.user_name, &endptr, 10);
            pw = getpwuid(userid);
        }

        if (config.group_name == NULL && pw != NULL) {
            groupid = pw->pw_gid;
        }
    }

    if (do_setgid) {
        if ((i = setgid(groupid)) < 0) {
            printf("Unable to set group ID: %s", strerror(i));
        }
    }

    endgrent();
    endpwent();

    if (do_setuid) {
        if (getuid() == 0 && initgroups(config.user_name, groupid) < 0) {
            printf("Unable to init group names (%s/%lu)", config.user_name,
                   groupid);
        }
        if ((i = setuid(userid)) < 0) {
            printf("Unable to set user ID: %s\n", strerror(i));
        }
    }
    return 0;
}

int is_valid_path(const char *path)
{
    struct stat st;

    if (path == NULL) {
        return 0;
    }
    if (stat(path, &st) != 0) {
        return 0;
    }
    if (!S_ISDIR(st.st_mode) || access(path, W_OK) == -1) {
        return 0;
    }
    return 1;
}

int create_pid_file(const char *path, const char *filename)
{
    char filepath[STDBUF];
    const char *fp = NULL;
    const char *fn = NULL;
    char pid_buffer[12];
    struct flock lock;
    int rval;
    int fd;

    memset(filepath, 0, STDBUF);

    if (!filename) {
        fn = config.pidfile;
    } else {
        fn = filename;
    }

    if (!path) {
        fp = config.pidpath;
    } else {
        fp = path;
    }

    if (is_valid_path(fp)) {
        snprintf(filepath, STDBUF - 1, "%s/%s", fp, fn);
    } else {
        printf("PID path \"%s\" isn't a writeable directory!", fp);
    }

    config.true_pid_name = strdup(filename);

    if ((fd = open(filepath, O_CREAT | O_WRONLY,
                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
        return ERROR;
    }

    /*
     * pid file locking 
     */
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    if (fcntl(fd, F_SETLK, &lock) == -1) {
        if (errno == EACCES || errno == EAGAIN) {
            rval = ERROR;
        } else {
            rval = ERROR;
        }
        close(fd);
        return rval;
    }
    snprintf(pid_buffer, sizeof(pid_buffer), "%d\n", (int)getpid());
    if (ftruncate(fd, 0) != 0) {
        return ERROR;
    }
    if (write(fd, pid_buffer, strlen(pid_buffer)) != 0) {
        return ERROR;
    }
    return SUCCESS;
}

int daemonize()
{
    pid_t pid;
    int fd;
    //extern char *pidfile, *pidpath;

    pid = fork();

    if (pid > 0) {
        exit(0);                /* parent */
    }

    //config.use_syslog = 1;
    if (pid < 0) {
        return ERROR;
    }

    /*
     * new process group 
     */
    setsid();

    /*
     * close file handles 
     */
    if ((fd = open("/dev/null", O_RDWR)) >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) {
            close(fd);
        }
    }

    if (config.pidfile) {
        return create_pid_file(config.pidpath, config.pidfile);
    }

    return SUCCESS;
}

