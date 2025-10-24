#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include "qubes-admin-authz-common.h"

#define MODE_DENY 0
#define MODE_QREXEC 1
#define MODE_ALLOW 2

int str2mode(const char* s, const char* log_name) {
    int mode = -1;
    if (strcmp(s, "deny") == 0) {
        mode = MODE_DENY;
    }
    if (strcmp(s, "qrexec") == 0) {
        mode = MODE_QREXEC;
    }
    if (strcmp(s, "allow") == 0) {
        mode = MODE_ALLOW;
    }
    if (log_name != NULL) {
        if (mode < 0) {
            printf("mode in %s not 'deny', 'qrexec' or 'allow'\n", log_name);
        } else {
            printf("mode read from %s\n", log_name);
        }
    }
    return mode;
}

int main() {
    int rc = -1;
    int mode = MODE_DENY;

    if (setvbuf(stdout, NULL, _IONBF, 0) != 0) {
        printf("failed to set stdout buffer mode\n");
        return 1;
    }

    char* env_mode_str = getenv("QUBES_ADMIN_AUTHZD_MODE");
    if (env_mode_str != NULL && env_mode_str[0] != '\0') {
        mode = str2mode(env_mode_str, "QUBES_ADMIN_AUTHZD_MODE");
        if (mode < 0) {
            return 1;
        }
    } else {
        char* confs[] = {
            "/usr/local/etc/qubes/admin-authzd.conf",
            "/etc/qubes/admin-authzd.conf",
        };
        for (size_t i = 0; i < sizeof(confs)/sizeof(confs[0]); i += 1) {
            int fd = open(confs[i], O_RDONLY);
            if (fd < 0) {
                if (errno == ENOENT) {
                    printf("%s does not exits\n", confs[i]);
                    continue;
                }
                printf("failed to read %s: %m\n", confs[i]);
                return 1;
            }
            char buf[100] = {};
            ssize_t read_ret = read(fd, &buf, sizeof(buf) - 1);
            if (read_ret < 0) {
                printf("failed to read from %s: %m\n", confs[i]);
                return 1;
            }
            char* eol = strchr(buf, '\n');
            if (eol != NULL) {
                *eol = '\0';
            }
            mode = str2mode(buf, confs[i]);
            if (mode < 0) {
                return 1;
            }
            break;
        }
    }

    struct sigaction chld_act = {
        .sa_handler = SIG_IGN,
        .sa_flags = SA_NOCLDWAIT,
    };
    if (sigaction(SIGCHLD, &chld_act, NULL) != 0) {
        printf("sigaction failed: %m\n");
        return 1;
    }

    int s = -1;
    s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s == -1) {
        printf("failed to open socket: %m\n");
        return 1;
    }

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
        .sun_path = SOCKET_PATH,
    };

    rc = bind(s,
              (struct sockaddr*)&addr,
              sizeof(addr.sun_family) + sizeof(SOCKET_PATH) - 1);
    if (rc != 0) {
        printf("failed to bind socket: %m\n");
        return 1;
    }

    if (listen(s, 100) != 0) {
        printf("failed to listen on socket: %m\n");
        return 1;
    }

    printf("mode: %s\n",
           mode == MODE_DENY ? "deny" :
           mode == MODE_QREXEC ? "qrexec" : "allow");

    int client = -1;
    while (true) {
        if (client >= 0) {
            if (close(client) != 0) {
                printf("close of client socket failed: %m\n");
            }
        }

        printf("waiting for new request\n");
        client = accept(s, NULL, NULL);
        if (client < 0) {
            printf("accept failed: %m\n");
            return 1;
        }

        printf("new request received\n");

        struct ucred cred = {};
        socklen_t cred_size = sizeof(cred);
        rc = getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &cred_size);
        if (rc == -1) {
            printf("failed to get peer credentials from socket: %m\n");
            continue;
        }
        if (cred_size != sizeof(cred)) {
            printf("failed to get peer credentials from socket: unexpected size\n");
            continue;
        }
        if (cred.uid != 0) {
            printf("client socket not opened by root\n");
            continue;
        }

        if (mode == MODE_DENY || mode == MODE_ALLOW) {
            char* res_str = mode == MODE_ALLOW ? "authorized" : "denied";
            ssize_t res_str_len = strlen(res_str);
            ssize_t write_rc = write(client, res_str, res_str_len);
            if (write_rc < 0) {
                printf("write failed: %m\n");
            } else if (write_rc != res_str_len) {
                printf("short write\n");
            }
            continue;
        }

        // mode == MODE_QREXEC

        pid_t pid = fork();
        if (pid == -1) {
            printf("fork failed: %m\n");
            continue;
        } else if (pid != 0) {
            continue;
        }

        // child

        int new_stdin = open("/dev/null", O_RDONLY);
        if (new_stdin < 0) {
            printf("child: failed to open /dev/null: %m\n");
            return 1;
        }
        if (dup2(new_stdin, 0) < 0) {
            printf("child: dup2(_, 0) failed: %m\n");
            return 1;
        }
        if (dup2(client, 1) < 0) {
            printf("child: dup2(_, 1) failed: %m\n");
            return 1;
        }
        if (close(new_stdin) != 0 || close(client) != 0) {
            printf("child: close failed: %m\n");
            return 1;
        }

        execlp("qrexec-client-vm", "qrexec-client-vm", "@default", "qubes.AuthorizeInVMAdminAccess", NULL);
        printf("child: exec failed: %m\n");
        return 1;
    }
}
