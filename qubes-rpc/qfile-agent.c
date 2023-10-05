#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <gui-fatal.h>
#include <libqubes-rpc-filecopy.h>

enum {
    PROGRESS_FLAG_NORMAL,
    PROGRESS_FLAG_INIT,
    PROGRESS_FLAG_DONE
};

void do_notify_progress(long long total, int flag)
{
    const char *du_size_env = getenv("FILECOPY_TOTAL_SIZE");
    const char *progress_type_env = getenv("PROGRESS_TYPE");
    const char *saved_stdout_env = getenv("SAVED_FD_1");
    int ignore;
    if (!progress_type_env)
        return;
    if (!strcmp(progress_type_env, "console") && du_size_env) {
        char msg[256];
        snprintf(msg, sizeof(msg), "sent %lld/%lld KB\r",
             total / 1024, strtoull(du_size_env, NULL, 0));
        ignore = write(2, msg, strlen(msg));
        if (flag == PROGRESS_FLAG_DONE)
            ignore = write(2, "\n", 1);
        if (ignore < 0) {
            /* silence gcc warning */
        }
    }
    if (!strcmp(progress_type_env, "gui") && saved_stdout_env) {
        char msg[256];
        snprintf(msg, sizeof(msg), "%lld\n", total);
        if (write(strtoul(saved_stdout_env, NULL, 0), msg, strlen(msg)) == -1
            && errno == EPIPE)
            exit(32);
    }
}

void notify_progress(int size, int flag)
{
    static long long total = 0;
    static long long prev_total = 0;
    total += size;
    if (total > prev_total + PROGRESS_NOTIFY_DELTA
        || (flag != PROGRESS_FLAG_NORMAL)) {
        // check for possible error from qfile-unpacker; if error occured,
        // exit() will be called, so don't bother with current state
        // (notify_progress can be called as callback from copy_file())
        if (flag == PROGRESS_FLAG_NORMAL)
            wait_for_result();
        do_notify_progress(total, flag);
        prev_total = total;
    }
}

int main(int argc, char **argv)
{
    int i;
    int ignore_symlinks = 0;
    int invocation_cwd_fd;
    char *arg_dirname_in;
    char *arg_dirname;
    char *arg_basename_in;
    char *arg_basename;

    qfile_pack_init();
    register_error_handler(qfile_gui_fatal);
    register_notify_progress(&notify_progress);
    notify_progress(0, PROGRESS_FLAG_INIT);
    invocation_cwd_fd = open(".", O_PATH | O_DIRECTORY);
    if (invocation_cwd_fd < 0)
        gui_fatal("open \".\"");
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ignore-symlinks")==0) {
            ignore_symlinks = 1;
            continue;
        }
        if (!*argv[i])
            gui_fatal("Invalid empty argument %i", i);

        arg_dirname_in = strdup(argv[i]);
        if (!arg_dirname_in)
            gui_fatal("strdup for dirname of %s", argv[i]);
        arg_dirname = dirname(arg_dirname_in);

        arg_basename_in = strdup(argv[i]);
        if (!arg_basename_in)
            gui_fatal("strdup for basename of %s", argv[i]);
        arg_basename = basename(arg_basename_in);

        if (fchdir(invocation_cwd_fd))
            gui_fatal("fchdir to %i", invocation_cwd_fd);
        if (chdir(arg_dirname))
            gui_fatal("chdir to %s", arg_dirname);
        do_fs_walk(arg_basename, ignore_symlinks);

        free(arg_dirname_in);
        free(arg_basename_in);
    }
    notify_end_and_wait_for_result();
    notify_progress(0, PROGRESS_FLAG_DONE);
    return 0;
}
