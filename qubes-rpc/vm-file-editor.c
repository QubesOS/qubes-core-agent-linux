#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <libqubes-rpc-filecopy.h>
#include "dvm2.h"

#define USER_HOME "/home/user"
#define TMP_LOC "/tmp/qopen/"
// #define DEBUG

static const char *cleanup_filename = NULL;

static void cleanup_file(void)
{
	if (cleanup_filename) {
		if (unlink(cleanup_filename) < 0)
			fprintf(stderr, "Failed to remove file at exit\n");
		cleanup_filename = NULL;
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
	struct stat dstat;
	int ret;

	remote_domain = getenv("QREXEC_REMOTE_DOMAIN");
	if (!remote_domain) {
		fprintf(stderr, "Cannot get remote domain name\n");
		exit(1);
	}
	if (!*remote_domain || index(remote_domain, '/'))
		goto fail;
	if (!strcmp(remote_domain, ".") || !strcmp(remote_domain, ".."))
		goto fail;

	len = strlen("/tmp")+1+strlen(remote_domain)+1;
	dir = malloc(len);
	if (!dir) {
		fprintf(stderr, "Cannot allocate memory\n");
		exit(1);
	}
	snprintf(dir, len, "/tmp/%s", remote_domain);

	ret=mkdir(dir, 0777);
	if (ret<0 && errno!=EEXIST) {
		perror("mkdir");
		exit(1);
	}
	if (stat(dir, &dstat)) {
		perror("stat dir");
		exit(1);
	}
	if (!S_ISDIR(dstat.st_mode)) {
		fprintf(stderr, "%s exists and is not a directory\n", dir);
		exit(1);
	}

	return dir;

fail:
	fprintf(stderr, "Invalid remote domain name: %s\n", remote_domain);
	exit(1);
}

char *get_filename(void)
{
	char buf[DVM_FILENAME_SIZE];
	static char *retname;
	int i;
	char *directory;
	size_t len;

	directory = get_directory();
	if (!read_all(0, buf, sizeof(buf)))
		exit(1);
	buf[DVM_FILENAME_SIZE-1] = 0;
	if (index(buf, '/')) {
		fprintf(stderr, "filename contains /");
		exit(1);
	}
	for (i=0; buf[i]!=0; i++) {
		// replace some characters with _ (eg mimeopen have problems with some of them)
		if (index(" !?\"#$%^&*()[]<>;`~|", buf[i]))
			buf[i]='_';
	}
	len = strlen(directory)+1+strlen(buf)+1;
	retname = malloc(len);
	if (!retname) {
		fprintf(stderr, "Cannot allocate memory\n");
		exit(1);
	}
	snprintf(retname, len, "%s/%s", directory, buf);
	free(directory);
	return retname;
}

void copy_file_by_name(const char *filename)
{
	int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		perror("open file");
		exit(1);
	}
	/* we now have created a new file, ensure we delete it at the end */
	cleanup_filename = filename;
	atexit(cleanup_file);
	if (!copy_fd_all(fd, 0))
        exit(1);
	close(fd);
}

void send_file_back(const char * filename)
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
main()
{
	struct stat stat_pre, stat_post, session_stat;
	char *filename = get_filename();
	int child, status, log_fd, null_fd;
	FILE *waiter_pidfile;

	copy_file_by_name(filename);
	if (stat(filename, &stat_pre)) {
		perror("stat pre");
		exit(1);
	}
#ifdef DEBUG
	fprintf(stderr, "time=%s, waiting for qubes-session\n", gettime());
#endif
	// wait for X server to starts (especially in DispVM)
	if (stat("/tmp/qubes-session-env", &session_stat)) {
		switch (child = fork()) {
			case -1:
				perror("fork");
				exit(1);
			case 0:
				waiter_pidfile = fopen("/tmp/qubes-session-waiter", "a");
				if (waiter_pidfile == NULL) {
					perror("fopen waiter_pidfile");
					exit(1);
				}
				fprintf(waiter_pidfile, "%d\n", getpid());
				fclose(waiter_pidfile);
				// check the second time, to prevent race
				if (stat("/tmp/qubes-session-env", &session_stat)) {
					// wait for qubes-session notify
					pause();
				}
				exit(0);
			default:
				waitpid(child, &status, 0);
				if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
					//propagate exit code from child
					exit(WEXITSTATUS(status));
				}
		}
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
			dup2(null_fd, 0);
			close(null_fd);

			log_fd = open("/tmp/mimeopen.log", O_CREAT | O_APPEND, 0666);
			if (log_fd == -1) {
				perror("open /tmp/mimeopen.log");
				exit(1);
			}
			dup2(log_fd, 1);
			close(log_fd);

			setenv("HOME", USER_HOME, 1);
			setenv("DISPLAY", ":0", 1);
			execl("/usr/bin/qubes-open", "qubes-open", filename, (char*)NULL);
			perror("execl");
			exit(1);
		default:
			waitpid(child, &status, 0);
			if (status != 0) {
				char cmd[512];
#ifdef USE_KDIALOG
				snprintf(cmd, sizeof(cmd),
						"HOME=/home/user DISPLAY=:0 /usr/bin/kdialog --sorry 'Unable to handle mimetype of the requested file (exit status: %d)!' > /tmp/kdialog.log 2>&1 </dev/null", status);
					("HOME=/home/user DISPLAY=:0 /usr/bin/kdialog --sorry 'Unable to handle mimetype of the requested file (exit status: %d)!' > /tmp/kdialog.log 2>&1 </dev/null", status);
#else
				snprintf(cmd, sizeof(cmd),
						"HOME=/home/user DISPLAY=:0 /usr/bin/zenity --error --text 'Unable to handle mimetype of the requested file (exit status: %d)!' > /tmp/kdialog.log 2>&1 </dev/null", status);
#endif
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
