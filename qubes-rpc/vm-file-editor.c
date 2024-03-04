#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <err.h>
#include <libqubes-rpc-filecopy.h>
#include "dvm2.h"

// #define DEBUG

static const char *cleanup_filename = NULL;
static const char *cleanup_dirname = NULL;

static void cleanup_file(void)
{
    if (cleanup_filename) {
        if (unlink(cleanup_filename) < 0)
            fprintf(stderr, "Failed to remove file at exit\n");
        cleanup_filename = NULL;
    }
    if (cleanup_dirname) {
        if (rmdir(cleanup_dirname) < 0)
            fprintf(stderr, "Failed to remove directory at exit\n");
        cleanup_dirname = NULL;
    }
}

const char *gettime(void)
{
    static char retbuf[60];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    snprintf(retbuf, sizeof(retbuf), "%lld.%06lld",
         (long long) tv.tv_sec, (long long) tv.tv_usec);
    return retbuf;
}

static char *get_directory(void)
{
    const char *remote_domain;
    char *dir;
    size_t len;
    char *ret;

    remote_domain = getenv("QREXEC_REMOTE_DOMAIN");
    if (!remote_domain) {
        fprintf(stderr, "Cannot get remote domain name\n");
        exit(1);
    }
    if (!*remote_domain || strchr(remote_domain, '/'))
        goto fail;
    if (!strcmp(remote_domain, ".") || !strcmp(remote_domain, ".."))
        goto fail;

    len = strlen("/tmp/-XXXXXX")+strlen(remote_domain)+1;
    dir = malloc(len);
    if (!dir) {
        fprintf(stderr, "Cannot allocate memory\n");
        exit(1);
    }
    if ((size_t)snprintf(dir, len, "/tmp/%s-XXXXXX", remote_domain) != len - 1)
        err(1, "snprintf");

    ret = mkdtemp(dir);
    if (ret == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    cleanup_dirname = strdup(ret);
    return ret;

fail:
    fprintf(stderr, "Invalid remote domain name: %s\n", remote_domain);
    exit(1);
}

static char *get_filename(int *view_only)
{
    char buf[DVM_FILENAME_SIZE];
    char *fname = buf;
    static char *retname;
    int i;
    char *directory;
    size_t const prefix_len = strlen(DVM_VIEW_ONLY_PREFIX);
    size_t len;

    directory = get_directory();
    if (!read_all(0, buf, sizeof(buf)))
        exit(1);
    buf[DVM_FILENAME_SIZE-1] = 0;
    if (strncmp(buf, DVM_VIEW_ONLY_PREFIX, prefix_len) == 0) {
        *view_only = 1;
        fname += prefix_len;
    }
    for (i=0; fname[i]!=0; i++) {
        // replace some characters with _ (eg mimeopen have problems with some of them)
        switch (fname[i]) {
        case '0' ... '9':
        case 'a' ... 'z':
        case 'A' ... 'Z':
        case '.':
        case '_':
        case '-':
        case '+':
        case '@':
            break;
        case '/':
            errx(1, "filename contains /");
        default:
            fname[i]='_';
            break;
        }
    }
    len = strlen(directory)+1+i+1;
    retname = malloc(len);
    if (!retname) {
        fprintf(stderr, "Cannot allocate memory\n");
        exit(1);
    }
    if ((size_t)snprintf(retname, len, "%s/%s", directory, fname) != len - 1)
        errx(1, "snprintf() failed!");
    free(directory);
    return retname;
}

static void copy_file_by_name(const char *filename)
{
    int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        perror("open file");
        exit(1);
    }
    /* we now have created a new file, ensure we delete it at the end */
    cleanup_filename = strdup(filename);
    atexit(cleanup_file);
    if (!copy_fd_all(fd, 0))
        exit(1);
    close(fd);
}

static void send_file_back(const char * filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open file");
        exit(1);
    }
    if (!copy_fd_all(1, fd))
        exit(1);
    close(fd);
    close(1);
}

int
main(void)
{
    struct stat stat_pre, stat_post;
    int view_only = 0;
    char *filename = get_filename(&view_only);
    int child, status, log_fd, null_fd;

    copy_file_by_name(filename);
    if (view_only) {
        // mark file as read-only so applications will signal it to the user
        if (chmod(filename, 0400))
            err(1, "chmod()");
    }
    if (stat(filename, &stat_pre)) {
        perror("stat pre");
        exit(1);
    }

#ifdef DEBUG
    fprintf(stderr, "time=%s, starting editor\n", gettime());
#endif
    switch (child = fork()) {
        case -1:
            perror("fork");
            exit(1);
        case 0:
            null_fd = open("/dev/null", O_RDONLY);
            if (null_fd < 0)
                err(1, "open(\"/dev/null\")");
            if (dup2(null_fd, 0) != 0)
                err(1, "dup2()");
            if (close(null_fd))
                err(1, "close()");

            log_fd = open("/tmp/mimeopen.log", O_CREAT | O_APPEND | O_NOFOLLOW, 0666);
            if (log_fd == -1) {
                perror("open /tmp/mimeopen.log");
                _exit(1);
            }
            dup2(log_fd, 1);
            close(log_fd);

            execl("/usr/bin/qubes-open", "qubes-open", filename, (char*)NULL);
            perror("execl");
            _exit(1);
        default:
            waitpid(child, &status, 0);
            if (status != 0) {
                char cmd[512];
#ifdef USE_KDIALOG
                int count = snprintf(cmd, sizeof(cmd),
                        "/usr/bin/kdialog --sorry 'Unable to handle mimetype of the requested file (exit status: %d)!' > /def/null 2>&1 </dev/null", status);
#else
                int count = snprintf(cmd, sizeof(cmd),
                        "/usr/bin/zenity --error --text 'Unable to handle mimetype of the requested file (exit status: %d)!' > /dev/null 2>&1 </dev/null", status);
#endif
                if (count <= 0 || (size_t)count >= sizeof(cmd))
                    err(1, "snprintf");
                status = system(cmd);
            }
    }

    if (stat(filename, &stat_post)) {
        perror("stat post");
        exit(1);
    }
    if (stat_pre.st_mtime != stat_post.st_mtime)
        send_file_back(filename);
    free(filename);
    return 0;
}
