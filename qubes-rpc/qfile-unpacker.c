#define _GNU_SOURCE
#include <grp.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/fsuid.h>
#include <gui-fatal.h>
#include <errno.h>
#include <libqubes-rpc-filecopy.h>

#define INCOMING_DIR_NAME "QubesIncoming"

static char *prepare_creds_return_dir(uid_t uid, uid_t myuid)
{
    const struct passwd *pwd;
    if (myuid != 0 && myuid != (uid_t)uid)
        gui_fatal("Refusing to change to UID other than the caller's UID");
    pwd = getpwuid(uid);
    if (!pwd) {
        perror("getpwuid");
        exit(1);
    }
    setenv("HOME", pwd->pw_dir, 1);
    setenv("USER", pwd->pw_name, 1);
    if (pwd->pw_uid != uid)
        gui_fatal("getpwuid() returned entry for wrong user");
    if (setgid(pwd->pw_gid) < 0)
        gui_fatal("Error setting group permissions");
    if (initgroups(pwd->pw_name, pwd->pw_gid) < 0)
        gui_fatal("Error initializing groups");
    setfsuid(pwd->pw_uid);
    if ((uid_t)setfsuid(-1) != uid)
        gui_fatal("Error setting filesystem level permissions");
    return pwd->pw_dir;
}

int main(int argc, char ** argv)
{
    char *home_dir;
    char *incoming_dir_root;
    char *incoming_dir;
    uid_t caller_uid = getuid(), uid = caller_uid;
    pid_t pid;
    const char *remote_domain;
    char *procdir_path;
    int procfs_fd;
    int i, ret;

    if (argc >= 3) {
        char *end, *user = argv[1];
        errno = 0;
        if (strcmp(user, "0") != 0) {
            unsigned long long u = strtoull(user, &end, 10);
            uid = (uid_t)u;
            if (user[0] < '1' || user[0] > '9' ||
                    errno != 0 || *end != '\0' || uid != u)
                gui_fatal("Invalid user ID argument");
        } else {
            uid = 0;
        }
        home_dir = prepare_creds_return_dir(uid, caller_uid);
        incoming_dir = argv[2];
    } else {
        home_dir = prepare_creds_return_dir(caller_uid, caller_uid);
        remote_domain = getenv("QREXEC_REMOTE_DOMAIN");
        if (!remote_domain) {
            gui_fatal("Cannot get remote domain name");
        }

        if (asprintf(&incoming_dir_root, "%s/%s", home_dir, INCOMING_DIR_NAME) < 0) {
            gui_fatal("Error allocating memory");
        }
        // mkdir() failing is harmless.  If the directory doesn't exist after
        // the call, the subsequent chdir() will fail.
        mkdir(incoming_dir_root, 0700);
        if (asprintf(&incoming_dir, "%s/%s", incoming_dir_root, remote_domain) < 0)
            gui_fatal("Error allocating memory");
        mkdir(incoming_dir, 0700);
    }

    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0)
            set_verbose(1);
        else if (strcmp(argv[i], "-w") == 0)
            if (i+1 < argc && argv[i+1][0] != '-') {
                set_wait_for_space(atoi(argv[i+1]));
                i++;
            } else
                set_wait_for_space(1);
        else
            gui_fatal("Invalid option %s", argv[i]);
    }

    if (chdir(incoming_dir))
        gui_fatal("Error chdir to %s", incoming_dir);

    if (mount(".", ".", NULL, MS_BIND | MS_NODEV | MS_NOEXEC | MS_NOSUID, NULL) < 0)
        gui_fatal("Failed to mount a directory %s", incoming_dir);

    /* parse the input in unprivileged child process, parent will hold root
     * access to unmount incoming dir */
    switch (pid=fork()) {
        case -1:
            gui_fatal("Failed to create new process");
        case 0:
            if (asprintf(&procdir_path, "/proc/%d/fd", getpid()) < 0) {
                gui_fatal("Error allocating memory");
            }
            procfs_fd = open(procdir_path, O_DIRECTORY | O_RDONLY | O_NOCTTY | O_CLOEXEC);
            if (procfs_fd < 0)
                perror("Failed to open /proc");
            else
                set_procfs_fd(procfs_fd);
            free(procdir_path);

            if (chroot("."))
                gui_fatal("Error chroot to %s", incoming_dir);
            if (setuid(uid) < 0) {
                /* no kdialog inside chroot */
                perror("setuid");
                exit(1);
            }
            return do_unpack();
    }
    if (waitpid(pid, &ret, 0) < 0) {
        gui_fatal("Failed to wait for child process");
    }
    if (umount2(".", MNT_DETACH) < 0)
        gui_fatal("Cannot umount incoming directory");
    if (!WIFEXITED(ret)) {
        gui_fatal("Child process exited abnormally");
    }
    return WEXITSTATUS(ret);
}
