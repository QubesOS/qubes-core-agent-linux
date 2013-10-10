
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

unsigned long crc32_sum;
int ignore_symlinks;

void notify_progress(int size, int flag);
void do_notify_progress(long long total, int flag);
void notify_end_and_wait_for_result();

void write_headers(struct file_header *hdr, char *filename);

int write_all_with_crc(int fd, void *buf, int size);

int single_file_processor(char *filename, struct stat *st);

void wait_for_result();

#endif /* _LIBQUBES_QFILE_UTILS_H */
