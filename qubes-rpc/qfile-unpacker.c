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
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <getopt.h>
#include <err.h>

#include <gui-fatal.h>
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
    if (setgid(pwd->pw_gid) < 0)
        gui_fatal("Error setting group permissions");
    if (initgroups(pwd->pw_name, pwd->pw_gid) < 0)
        gui_fatal("Error initializing groups");
    if (setfsuid(pwd->pw_uid) < 0)
        gui_fatal("Error setting filesystem level permissions");
    return pwd->pw_dir;
}

static void set_wait_for_space_str(const char *str)
{
    if (strcmp(str, "0") == 0) {
        set_wait_for_space(0);
        return;
    }
    if (str[0] >= '1' && str[0] <= '9') {
        errno = 0;
        char *endp;
        long res = strtol(str, &endp, 10);
        if (errno == 0 && *endp == '\0' && res > 0 && res <= INT_MAX) {
            set_wait_for_space((int)res);
            return;
        }
    }
    errx(1, "Space amount %s is invalid or exceeds %d bytes", str, INT_MAX);
}

enum {
    opt_allow_unsafe_characters = 256,
    opt_allow_unsafe_symlinks,
    opt_no_allow_unsafe_characters,
    opt_no_allow_unsafe_symlinks,
};

const struct option opts[] = {
    { "no-allow-all-names", no_argument, NULL, opt_no_allow_unsafe_characters },
    { "allow-all-names", no_argument, NULL, opt_allow_unsafe_characters },
    { "no-allow-unsafe-symlinks", no_argument, NULL, opt_no_allow_unsafe_symlinks },
    { "allow-unsafe-symlinks", no_argument, NULL, opt_allow_unsafe_symlinks },
    { "verbose", no_argument, NULL, 'v' },
    { "wait-for-space", required_argument, NULL, 'w' },
    { NULL, 0, NULL, 0 },
};

uid_t parse_uid(const char *user)
{
    if (strcmp(user, "0") == 0)
        return 0;
    errno = 0;
    char *end = NULL;
    unsigned long long u = strtoull(user, &end, 10);
    uid_t uid = (uid_t)u;
    if (user[0] < '1' || user[0] > '9' ||
            errno != 0 || *end != '\0' || uid != u)
        gui_fatal("Invalid user ID argument");
    return uid;
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
    int flags = COPY_ALLOW_SYMLINKS | COPY_ALLOW_DIRECTORIES;
    if (argc < 1)
        errx(EXIT_FAILURE, "NULL argv[0] passed to execve()");
    if (argc >= 3 && argv[1][0] >= '0' && argv[1][0] <= '9') {
        // Legacy case: parse options by hand
        uid = parse_uid(argv[1]);
        incoming_dir = argv[2];

        for (i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-v") == 0)
                set_verbose(1);
            else if (strcmp(argv[i], "-w") == 0) {
                const char *next = argv[i + 1];
                if (next != NULL && next[0] != '-') {
                    set_wait_for_space_str(next);
                    i++;
                } else {
                    set_wait_for_space(1);
                }
            } else {
                gui_fatal("Invalid option %s", argv[i]);
            }
        }
    } else {
        incoming_dir = NULL;
        // Modern case: use getopt(3)
        for (;;) {
            if (optind < 1 || optind > argc) {
                // FIXME: is this actually impossible?
                assert(!"invalid optind() value?");
                abort();
            }
            int longindex = -1;
            const char *const last = argv[optind];
            int opt = getopt_long(argc, argv, "+vw:", opts, &longindex);
            if (opt == -1) {
                if (argc <= optind)
                    break;
                if (argc - optind > 2)
                    errx(1, "Wrong number of non-option arguments (expected no more than 2, got %d)",
                         argc - optind);
                if (argv[optind][0] != '\0')
                    uid = parse_uid(argv[optind]);
                // might be NULL
                incoming_dir = argv[optind + 1];
                break;
            }
            if (opt == '?' || opt == ':')
                return EXIT_FAILURE;
            if (longindex != -1) {
                const char *expected = opts[longindex].name;
                if (strncmp(expected, last + 2, strlen(expected)) != 0)
                    errx(1, "Option %s must be passed as --%s", last, expected);
            }
            switch (opt) {
            case 'v':
                set_verbose(1);
                break;
            case opt_allow_unsafe_characters:
                flags |= COPY_ALLOW_UNSAFE_CHARACTERS;
                break;
            case opt_allow_unsafe_symlinks:
                flags |= COPY_ALLOW_UNSAFE_SYMLINKS;
                break;
            case opt_no_allow_unsafe_characters:
                flags &= ~COPY_ALLOW_UNSAFE_CHARACTERS;
                break;
            case opt_no_allow_unsafe_symlinks:
                flags &= ~COPY_ALLOW_UNSAFE_SYMLINKS;
                break;
            case 'w':
                set_wait_for_space_str(optarg);
                break;
            }
        }
    }
    home_dir = prepare_creds_return_dir(uid, caller_uid);
    if (incoming_dir == NULL) {
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
            return do_unpack_ext(flags);
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
