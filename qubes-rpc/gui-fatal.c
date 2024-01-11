#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

static void fix_display(void)
{
    setenv("DISPLAY", ":0", 1);
}

static void produce_message(const char *type, const char *fmt, va_list args)
{
    char *dialog_msg;
    const char *progress_type = getenv("PROGRESS_TYPE");
    char buf[1024];
    (void)vsnprintf(buf, sizeof(buf), fmt, args);

    if (asprintf(&dialog_msg, "%s: %s: %s (error type: %s)", program_invocation_short_name, type, buf, strerror(errno)) < 0)
    {
        fprintf(stderr, "Failed to allocate memory for error message :(\n");
        return;
    }

    fprintf(stderr, "%s\n", dialog_msg);

    if (progress_type && !strcmp(progress_type, "gui"))
    {
        switch (fork())
        {
        case -1:
            exit(1); // what else
        case 0:
            if (geteuid() == 0) {
                if (setuid(getuid()) != 0) {
                    perror("setuid failed, not calling kdialog/zenity");
                    exit(1);
                }
            }
            fix_display();
#ifdef USE_KDIALOG
            execlp("/usr/bin/kdialog", "kdialog", "--sorry", dialog_msg, NULL);
#else
            execlp("/usr/bin/zenity", "zenity", "--error", "--text", dialog_msg, NULL);
#endif
            exit(1);
        default:;
        }
    }
    free(dialog_msg);
}

void gui_fatal(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    produce_message("Fatal error", fmt, args);
    va_end(args);
    exit(1);
}

void qfile_gui_fatal(const char *fmt, va_list args)
{
    produce_message("Fatal error", fmt, args);
    exit(1);
}

void gui_nonfatal(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    produce_message("Information", fmt, args);
    va_end(args);
}
