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
	}
	if (!strcmp(progress_type_env, "gui") && saved_stdout_env) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%lld\n", total);
		ignore = write(strtoul(saved_stdout_env, NULL, 0), msg,
				strlen(msg));
	}
	if (ignore < 0) {
		/* silence gcc warning */
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


char *get_abs_path(const char *cwd, const char *pathname)
{
	char *ret;
	if (pathname[0] == '/')
		return strdup(pathname);
	if (asprintf(&ret, "%s/%s", cwd, pathname) < 0)
		return NULL;
	else
		return ret;
}

int main(int argc, char **argv)
{
	int i;
	char *entry;
	char *cwd;
	char *sep;
	int ignore_symlinks = 0;

	qfile_pack_init();
	register_error_handler(qfile_gui_fatal);
	register_notify_progress(&notify_progress);
	notify_progress(0, PROGRESS_FLAG_INIT);
	cwd = getcwd(NULL, 0);
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--ignore-symlinks")==0) {
			ignore_symlinks = 1;
			continue;
		}

		entry = get_abs_path(cwd, argv[i]);

		do {
			sep = rindex(entry, '/');
			if (!sep)
				gui_fatal
				    ("Internal error: nonabsolute filenames not allowed");
			*sep = 0;
		} while (sep[1] == 0);
		if (entry[0] == 0) {
			if (chdir("/") < 0) {
				gui_fatal("Internal error: chdir(\"/\") failed?!");
			}
		} else if (chdir(entry))
			gui_fatal("chdir to %s", entry);
		do_fs_walk(sep + 1, ignore_symlinks);
		free(entry);
	}
	notify_end_and_wait_for_result();
	notify_progress(0, PROGRESS_FLAG_DONE);
	return 0;
}


