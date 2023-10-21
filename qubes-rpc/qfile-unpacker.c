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

char *prepare_creds_return_dir(int uid)
{
    const struct passwd *pwd;
    uid_t myuid = getuid();
    if (myuid != 0 && myuid != (uid_t)uid)
        gui_fatal("Refusing to change to UID other than the caller's UID");
    pwd = getpwuid(uid);
    if (!pwd) {
        perror("getpwuid");
        exit(1);
    }
    setenv("HOME", pwd->pw_dir, 1);
    setenv("USER", pwd->pw_name, 1);
    if (setgid(pwd->pw_gid) < 0)
        gui_fatal("Error setting group permissions");
    if (initgroups(pwd->pw_name, pwd->pw_gid) < 0)
        gui_fatal("Error initializing groups");
    if (setfsuid(pwd->pw_uid) < 0)
        gui_fatal("Error setting filesystem level permissions");
    return pwd->pw_dir;
}

int main(int argc, char ** argv)
{
    char *home_dir;
    char *incoming_dir_root;
    char *incoming_dir;
    int uid, ret;
    pid_t pid;
    const char *remote_domain;
    char *procdir_path;
    int procfs_fd;
    int i;

    if (argc >= 3) {
        errno = 0;
        uid = strtol(argv[1], NULL, 10);
        if (errno)
            gui_fatal("Invalid user ID argument");
        home_dir = prepare_creds_return_dir(uid);
        incoming_dir = argv[2];
    } else {
        uid = getuid();
        home_dir = prepare_creds_return_dir(uid);
        remote_domain = getenv("QREXEC_REMOTE_DOMAIN");
        if (!remote_domain) {
            gui_fatal("Cannot get remote domain name");
        }

        if (asprintf(&incoming_dir_root, "%s/%s", home_dir, INCOMING_DIR_NAME) < 0) {
            gui_fatal("Error allocating memory");
        }
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
            procfs_fd = open(procdir_path, O_DIRECTORY | O_RDONLY);
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
