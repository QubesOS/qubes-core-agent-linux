#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdlib.h>
#include <libqubes-rpc-filecopy.h>
#include <unistd.h>
#include <gui-fatal.h>
#include "dvm2.h"

void send_file(const char *fname)
{
	const char *base;
	char sendbuf[DVM_FILENAME_SIZE];
	int fd = open(fname, O_RDONLY);
	if (fd < 0)
		gui_fatal("open %s", fname);
	base = rindex(fname, '/');
	if (!base)
		base = fname;
	else
		base++;
	if (strlen(base) >= DVM_FILENAME_SIZE)
		base += strlen(base) - DVM_FILENAME_SIZE + 1;
        strncpy(sendbuf,base,DVM_FILENAME_SIZE); /* fills out with NULs */
	if (!write_all(1, sendbuf, DVM_FILENAME_SIZE))
		gui_fatal("send filename to dispVM");
	if (!copy_fd_all(1, fd))
		gui_fatal("send file to dispVM");
	close(1);
	close(fd);
}

int copy_and_return_nonemptiness(int tmpfd)
{
	struct stat st;
	if (!copy_fd_all(tmpfd, 0))
		gui_fatal("receiving file from dispVM");
	if (fstat(tmpfd, &st))
		gui_fatal("fstat");
	close(tmpfd);

	return st.st_size > 0;
}

void recv_file_nowrite(const char *fname)
{
	char *tempfile;
	char *errmsg;
	int tmpfd = -1;

	if (asprintf(&tempfile, "/tmp/file_edited_in_dvm.XXXXXX") != -1)
		tmpfd = mkstemp(tempfile);
	if (tmpfd < 0)
		gui_fatal("unable to create any temporary file, aborting");
	if (!copy_and_return_nonemptiness(tmpfd)) {
		unlink(tempfile);
		return;
	}
	if (asprintf(&errmsg,
		 "The file %s has been edited in Disposable VM and the modified content has been received, "
		 "but this file is in nonwritable directory and thus cannot be modified safely. The edited file has been "
		 "saved to %s", fname, tempfile) != -1)
        gui_nonfatal(errmsg);
}

void actually_recv_file(const char *fname, const char *tempfile, int tmpfd)
{
	if (!copy_and_return_nonemptiness(tmpfd)) {
		unlink(tempfile);
		return;
	}
	if (rename(tempfile, fname))
		gui_fatal("rename");
}

void recv_file(const char *fname)
{
	int tmpfd = -1;
	char *tempfile;
	if (asprintf(&tempfile, "%s.XXXXXX", fname) != -1) {
		tmpfd = mkstemp(tempfile);
	}
	if (tmpfd < 0)
		recv_file_nowrite(fname);
	else
		actually_recv_file(fname, tempfile, tmpfd);
}

void talk_to_daemon(const char *fname)
{
	send_file(fname);
	recv_file(fname);
}

int main(int argc, char ** argv)
{
	signal(SIGPIPE, SIG_IGN);
	if (argc!=2)
		gui_fatal("OpenInVM - no file given?");
	talk_to_daemon(argv[1]);
	return 0;
}
