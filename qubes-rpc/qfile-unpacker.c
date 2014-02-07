#define _GNU_SOURCE
#include <grp.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <sys/fsuid.h>
#include <gui-fatal.h>
#include <errno.h>
#include <libqubes-rpc-filecopy.h>
#define INCOMING_DIR_ROOT "/home/user/QubesIncoming"
int prepare_creds_return_uid(const char *username)
{
	const struct passwd *pwd;
	pwd = getpwnam(username);
	if (!pwd) {
		perror("getpwnam");
		exit(1);
	}
	setenv("HOME", pwd->pw_dir, 1);
	setenv("USER", username, 1);
	if (setgid(pwd->pw_gid) < 0)
		gui_fatal("Error setting group permissions");
	if (initgroups(username, pwd->pw_gid) < 0)
		gui_fatal("Error initializing groups");
	if (setfsuid(pwd->pw_uid) < 0)
		gui_fatal("Error setting filesystem level permissions");
	return pwd->pw_uid;
}

int main(int argc, char ** argv)
{
	char *incoming_dir;
	int uid;
	const char *remote_domain;

	uid = prepare_creds_return_uid("user");

	remote_domain = getenv("QREXEC_REMOTE_DOMAIN");
	if (!remote_domain) {
		gui_fatal("Cannot get remote domain name");
		exit(1);
	}
	mkdir(INCOMING_DIR_ROOT, 0700);
	if (asprintf(&incoming_dir, "%s/%s", INCOMING_DIR_ROOT, remote_domain) < 0)
		gui_fatal("Error allocating memory"); 
	mkdir(incoming_dir, 0700);
	if (chdir(incoming_dir))
		gui_fatal("Error chdir to %s", incoming_dir); 
	if (chroot(incoming_dir)) //impossible
		gui_fatal("Error chroot to %s", incoming_dir);
	if (setuid(uid) < 0)
		gui_fatal("Error changing permissions to '%s'", "user");
	return do_unpack();
}
