
#ifndef _LIBQUBES_QFILE_UTILS_H
#define _LIBQUBES_QFILE_UTILS_H 1

#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <string.h>
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

extern unsigned long crc32_sum;
extern int ignore_symlinks;

void notify_progress(int size, int flag);
void do_notify_progress(long long total, int flag);
void notify_end_and_wait_for_result(void);

void write_headers(const struct file_header *hdr, const char *filename);

int write_all_with_crc(int fd, const void *buf, int size);

int single_file_processor(const char *filename, const struct stat *st);

void wait_for_result(void);

#endif /* _LIBQUBES_QFILE_UTILS_H */
