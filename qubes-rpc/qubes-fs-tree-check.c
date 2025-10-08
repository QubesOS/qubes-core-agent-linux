#define _GNU_SOURCE 1
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>

#include <libgen.h>
#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>

#include <qubes/pure.h>
#include <libqubes-rpc-filecopy.h>
static bool
simple_fs_walk(int fd, bool ignore_symlinks, const char *name, int flags,
               unsigned long long *size);

// This code operates on completely untrusted input.
// Therefore, it is critical to escape everything before displaying it.
// Use this function for that purpose.
char *simple_strvis(const char *untrusted_str)
{
    size_t len = strlen(untrusted_str);
    if (len > PTRDIFF_MAX / 4 - 3)
        errx(1, "String too long to escape");
    size_t out_len = len * 4 + 3;
    char *p = malloc(out_len);
    if (p == NULL)
        err(1, "malloc(%zu)", out_len);
    char *out_cursor = p;
    char *out_end = p + out_len;
    const char *in_cursor = untrusted_str;
    *out_cursor++ = '"';
    for (;;) {
        char c = *in_cursor++;
        switch (c) {
        case '\0':
            assert(out_end - out_cursor >= 2);
            *out_cursor++ = '"';
            *out_cursor++ = '\0';
            return p;
        case '"':
        case '\\':
            assert(out_end - out_cursor >= 2);
            *out_cursor++ = '\\';
            *out_cursor++ = in_cursor[-1];
            break;
        case '\n':
            assert(out_end - out_cursor >= 2);
            *out_cursor++ = '\\';
            *out_cursor++ = 'n';
            break;
        case '\t':
            assert(out_end - out_cursor >= 2);
            *out_cursor++ = '\\';
            *out_cursor++ = 't';
            break;
        default:
            assert(out_end - out_cursor >= 4);
            if (c >= 0x20 && c <= 0x7E)
                *out_cursor++ = c;
            else {
                *out_cursor++ = '\\';
                *out_cursor++ = '0' + ((uint8_t)c >> 6);
                *out_cursor++ = '0' + ((uint8_t)c >> 3 & 7);
                *out_cursor++ = '0' + ((uint8_t)c & 7);
            }
        }
    }
}
bool machine = false;
bool ignore_symlinks = false;

static bool
process_dirent(const char *d_name, int fd, int flags, const char *name,
               bool ignore_symlinks, const char *escaped, unsigned long long *size)
{
    bool bad = false;
    struct stat statbuf;
    int res = fstatat(fd, d_name, &statbuf, AT_SYMLINK_NOFOLLOW);
    if (res < 0)
        err(1, "fstatat(%s)", escaped);
    switch (statbuf.st_mode & S_IFMT) {
    case S_IFLNK:
        if (ignore_symlinks)
            return false; // do not check path
        if ((flags & COPY_ALLOW_SYMLINKS) == 0)
            errx(1, "Cannot copy symbolic link %s", escaped);
        break;
    case S_IFDIR:
        if ((flags & COPY_ALLOW_DIRECTORIES) == 0)
            errx(1, "Cannot copy directory %s", escaped);
        break;
    case S_IFREG:
        break;
    default:
        // In machine readable mode, ignore these
        bad = !machine && (flags & COPY_ALLOW_UNSAFE_CHARACTERS) == 0 &&
            !qubes_pure_string_safe_for_display(d_name, 0);
        if (bad)
            warnx("%s is not safe for display", escaped);
        return bad;
    }
    if ((flags & COPY_ALLOW_UNSAFE_CHARACTERS) == 0 &&
            !qubes_pure_string_safe_for_display(d_name, 0)) {
        if (!machine)
            warnx("%s is not safe for display", escaped);
        bad = true;
    }
    if (S_ISDIR(statbuf.st_mode)) {
        int sub_file = openat(fd, d_name, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_RDONLY);
        if (sub_file < 0)
            err(1, "open(%s)", escaped);
        // If "bad" is true, return "true", but still do the
        // FS walk to get the amount of data to copy.
        return simple_fs_walk(sub_file, ignore_symlinks, name, flags, size) || bad;
    } else {
        // __builtin_add_overflow uses infinite signed precision,
        // so a negative number would not cause overflow.
        if (statbuf.st_size < 0)
            errx(1, "Negative size?");
        // If this overflows, then we definitely want to error out instead of
        // filling up the receiver's disk.
        if (__builtin_add_overflow(*size, statbuf.st_size, size))
            errx(1, "Refusing to copy over 2**64 bytes");
        if (S_ISREG(statbuf.st_mode) || ignore_symlinks)
            return bad;
    }
    if (statbuf.st_size > SSIZE_MAX - 1)
        errx(1, "symbolic link too large for readlink()");
    size_t link_size = (size_t)(statbuf.st_size + 1);
    char *buf = malloc(link_size);
    if (buf == NULL)
        err(1, "malloc(%zu)", link_size);
    ssize_t link_res = readlinkat(fd, d_name, buf, link_size);
    if (link_res < 0)
        err(1, "readlink(%s)", escaped);
    if (link_res != statbuf.st_size)
        errx(1, "readlink(%s) returned wrong size", escaped);
    buf[link_res] = '\0'; // add NUL terminator
    bad = !qubes_pure_string_safe_for_display(buf, 0);
    // charset checks done already, do not repeat them
    if (qubes_pure_validate_symbolic_link_v2((const uint8_t *)name,
                                             (const uint8_t *)buf,
                                             QUBES_PURE_ALLOW_UNSAFE_CHARACTERS) < 0)
        errx(1, "Refusing to copy unsafe symbolic link %s", escaped);
    free(buf);
    return bad;
}

static bool
simple_fs_walk(int fd, bool ignore_symlinks, const char *name, int flags,
               unsigned long long *size)
{
    DIR *dir = fdopendir(fd);
    bool bad = false;
    if (dir == NULL)
        err(1, "fdopendir()");
    for (;;) {
        errno = 0;
        struct dirent *d = readdir(dir);
        if (d == NULL) {
            if (errno)
                err(1, "readdir()");
            break;
        }
        if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
            continue; /* skip "." and ".." */
        char *full_name = d->d_name;
        if (name != NULL && asprintf(&full_name, "%s/%s", name, d->d_name) < 1)
            err(1, "asprintf() failed (out of memory?)");
        char *escaped = simple_strvis(full_name);
        if (process_dirent(d->d_name, fd, flags, full_name, ignore_symlinks,
                           escaped, size))
            bad = true;
        if (full_name != d->d_name)
            free(full_name);
        free(escaped);
    }
    closedir(dir);
    return bad;
}

const struct option opts[] = {
    {"machine-readable", no_argument, NULL, 'm'},
    {"ignore-symlinks", no_argument, NULL, 'n'},
    {"no-ignore-symlinks", no_argument, NULL, 's'},
    {"allow-symlinks", no_argument, NULL, 'a'},
    {"no-allow-symlinks", no_argument, NULL, 'A'},
    {"allow-directories", no_argument, NULL, 'd'},
    {"no-allow-directories", no_argument, NULL, 'D'},
    {"allow-all-names", no_argument, NULL, 'u'},
    {"no-allow-all-names", no_argument, NULL, 'U'},
    {"help", no_argument, NULL, 'h'},
    {0, 0, NULL, 0},
};

int main(int argc, char **argv)
{
    if (argc < 2)
        errx(1, "not enough arguments");
    const char *last;
    int flags = 0;
    for (;;) {
        int longindex = sizeof(opts)/sizeof(opts[0]) - 1;
        assert(optind >= 1 && optind <= argc);
        last = argv[optind];
        int r = getopt_long(argc, argv, "+", opts, &longindex);
        if (r == -1)
            break;
        switch (r) {
        case ':':
        case '?':
            return 1;
        case 'm':
            machine = true;
            break;
        case 'n':
            ignore_symlinks = true;
            break;
        case 's':
            ignore_symlinks = false;
            break;
        case 'a':
            flags |= COPY_ALLOW_SYMLINKS;
            break;
        case 'A':
            flags &= ~COPY_ALLOW_SYMLINKS;
            break;
        case 'd':
            flags |= COPY_ALLOW_DIRECTORIES;
            break;
        case 'D':
            flags &= ~COPY_ALLOW_DIRECTORIES;
            break;
        case 'u':
            flags |= COPY_ALLOW_UNSAFE_CHARACTERS;
            break;
        case 'U':
            flags &= ~COPY_ALLOW_UNSAFE_CHARACTERS;
            break;
        case 'h':
            fputs("Usage:\n"
                  "  --help                  Print this message\n"
                  "  --machine-readable      Print the number of bytes to copy on stdout\n"
                  "  --ignore-symlinks       Ignore symbolic links; overrides previous --no-ignore-symlinks\n"
                  "  --no-ignore-symlinks    Do not ignore symbolic links; overrides previous --ignore-symlinks\n"
                  "  --allow-directories     Allow directories; overrides previous --no-allow-directories\n"
                  "  --no-allow-directories  Do not allow directories; overrides previous --allow-directories\n"
                  "  --allow-all-names       Allow all-names; overrides previous --no-allow-all-names\n"
                  "  --no-allow-all-names    Do not allow all-names; overrides previous --allow-all-names\n",
                  stderr);
            fflush(stderr);
            return ferror(stderr) ? 1 : 0;
        default:
            abort();
        }
    }
    if (argc <= optind)
        errx(1, "No paths provided");
    assert(last != NULL);
    if (strcmp(last, "--") != 0) {
        for (int j = optind; j < argc; ++j)
            if (argv[j][0] == '-')
                errx(1, "argument %d begins with - but first argument is not --", j);
    }
    bool bad = false;
    unsigned long long size = 0;
    for (int i = optind; i < argc; ++i) {
        size_t len = strlen(argv[i]);
        if (len < 3 && memcmp("..", argv[i], len) == 0) {
            if (len == 0)
                errx(1, "Empty string (passed as argument %d) is not a valid path", i);
            else
                errx(1, "Argument %d is \"%s\", which is not allowed.  Try operating from the parent directory.", i, argv[i]);
        }
        len++;
        char *escaped = simple_strvis(argv[i]);
        char *dup1 = malloc(len), *dup2 = malloc(len);
        if (dup1 == NULL || dup2 == NULL)
            err(1, "malloc(%zu)", len);
        char *bname = basename(memcpy(dup1, argv[i], len));
        char *dname = dirname(memcpy(dup2, argv[i], len));
        size_t bname_len = strlen(bname);
        if (bname_len < 3 && memcmp("..", bname, bname_len) == 0)
            errx(1, "Refusing to copy path with basename empty, ., or ..");
        int dir_fd = open(dname, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY);
        if (dir_fd < 0)
            err(1, "open(%s)", escaped);
        if (process_dirent(bname, dir_fd, flags, argv[i], ignore_symlinks,
                    escaped, &size))
            bad = true;
        free(dup2);
        free(dup1);
        free(escaped);
    }
    if (machine)
        printf("%llu\n", size);
    if (fflush(NULL) || ferror(stdout) || ferror(stderr))
        errx(1, "I/O error on standard stream");
    return bad ? 2 : 0;
}
