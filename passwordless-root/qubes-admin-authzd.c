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
#include <stdint.h>

#include <qubesdb-client.h>

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
            fprintf(stderr,
                    "mode in %s not 'deny', 'qrexec' or 'allow'\n",
                    log_name);
        } else {
            fprintf(stderr, "mode read from %s\n", log_name);
        }
    }
    return mode;
}

int main() {
    int rc = -1;
    int mode = -1;
    uint64_t client_num = 0;

    char* env_mode_str = getenv("QUBES_ADMIN_AUTHZD_MODE");
    if (env_mode_str != NULL && env_mode_str[0] != '\0') {
        mode = str2mode(env_mode_str, "QUBES_ADMIN_AUTHZD_MODE");
        if (mode < 0) {
            return 1;
        }
    }

    char* confs[] = {
        "/run/qubes-admin-authzd.conf",
        "/usr/local/etc/qubes/admin-authzd.conf",
        "/etc/qubes/admin-authzd.conf",
    };
    for (size_t i = 0;
         mode == -1 && i < sizeof(confs)/sizeof(confs[0]);
         i += 1)
    {
        int fd = open(confs[i], O_RDONLY);
        if (fd < 0) {
            if (errno == ENOENT) {
                fprintf(stderr, "%s does not exits\n", confs[i]);
                continue;
            }
            fprintf(stderr, "failed to read %s: %m\n", confs[i]);
            return 1;
        }
        char buf[100] = {};
        ssize_t read_ret = read(fd, &buf, sizeof(buf) - 1);
        if (read_ret < 0) {
            fprintf(stderr, "failed to read from %s: %m\n", confs[i]);
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
    }

    struct sigaction chld_act = {
        .sa_handler = SIG_IGN,
        .sa_flags = SA_NOCLDWAIT,
    };
    if (sigaction(SIGCHLD, &chld_act, NULL) != 0) {
        fprintf(stderr, "sigaction failed: %m\n");
        return 1;
    }

    int s = -1;
    s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s == -1) {
        fprintf(stderr, "failed to open socket: %m\n");
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
        fprintf(stderr, "failed to bind socket: %m\n");
        return 1;
    }

    if (listen(s, 100) != 0) {
        fprintf(stderr, "failed to listen on socket: %m\n");
        return 1;
    }

    fprintf(stderr, "mode: %s\n",
            mode == MODE_DENY ? "deny" :
            mode == MODE_QREXEC ? "qrexec" : "allow");

    int client = -1;
    while (true) {
        if (client >= 0) {
            if (close(client) != 0) {
                fprintf(stderr,
                        "client %w64u: close of client socket failed: %m\n",
                        client_num);
            }
        }

        fprintf(stderr, "waiting for new client\n");
        client = accept(s, NULL, NULL);
        if (client < 0) {
            fprintf(stderr, "accept failed: %m\n");
            return 1;
        }
        client_num += 1;

        fprintf(stderr, "client %w64u: connected\n", client_num);

        struct ucred cred = {};
        socklen_t cred_size = sizeof(cred);
        rc = getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &cred_size);
        if (rc == -1) {
            fprintf(stderr,
                    "client %w64u: "
                    "failed to get peer credentials from socket: %m\n",
                    client_num);
            continue;
        }
        if (cred_size != sizeof(cred)) {
            fprintf(stderr,
                    "clinet %w64u: failed to get peer credentials from socket: "
                    "unexpected size\n",
                    client_num);
            continue;
        }
        if (cred.uid != 0) {
            fprintf(stderr,
                    "client %w64u: client socket not opened by root\n",
                    client_num);
            continue;
        }

        pid_t pid = fork();
        if (pid == -1) {
            fprintf(stderr, "client %w64u: fork failed: %m\n", client_num);
            continue;
        } else if (pid != 0) {
            continue;
        }

        // child

        FILE* client_f = fdopen(client, "r+");
        if (client_f == NULL) {
            fprintf(stderr,
                    "client %w64u: failed to create stream from socket: %m\n",
                    client_num);
            return 1;
        }

        char req[100] = "qubes.AuthorizeAdminAccess+";
        size_t req_prefix_len = strlen(req);

        if (fgets(&req[req_prefix_len],
                  sizeof(req) - req_prefix_len,
                  client_f) == NULL)
        {
            fprintf(stderr,
                    "client %w64u: failed to read from socket\n",
                    client_num);
            return 1;
        }
        size_t req_len = strlen(req); // strlen(req) > 0 because of prefix
        if (req[req_len - 1] != '\n') {
            fprintf(stderr,
                    "client %w64u: received incomplete request\n",
                    client_num);
            return 1;
        }
        req[req_len - 1] = '\0';
        req_len -= 1;

        // Since the source is trusted (we received it from the PAM module
        // running as root, which gets it from it's config) not strictly
        // needed. Probably still nicer to error our early.
        for (size_t i = req_prefix_len; i < req_len; i += 1) {
            switch (req[i]) {
                case 'a' ... 'z':
                case 'A' ... 'Z':
                case '_':
                case '-':
                case '.':
                case '+':
                    continue;
            }
            fprintf(stderr,
                    "client %w64u: invalid character in request\n",
                    client_num);
            return 1;
        }

        fprintf(stderr,
                "client %w64u: request received: %s\n",
                client_num,
                &req[req_prefix_len]);

        if (mode == MODE_DENY || mode == MODE_ALLOW) {
            const char* res_str = mode == MODE_ALLOW ? "authorized" : "denied";
            if (fprintf(client_f, "%s\n", res_str) < 0 ||
                        fflush(client_f) != 0)
            {
                fprintf(stderr, "client %w64u: write failed: %m\n", client_num);
                return 1;
            }
            fprintf(stderr,
                    "client %w64u: answered '%s'\n",
                    client_num,
                    res_str);
            return 0;
        }

        // mode == MODE_QREXEC

        int new_stdin = open("/dev/null", O_RDONLY);
        if (new_stdin < 0) {
            fprintf(stderr,
                    "client %w64u: failed to open /dev/null: %m\n",
                    client_num);
            return 1;
        }
        if (dup2(new_stdin, 0) < 0) {
            fprintf(stderr,
                    "client %w64u: dup2(_, 0) failed: %m\n",
                    client_num);
            return 1;
        }
        if (dup2(client, 1) < 0) {
            fprintf(stderr,
                    "client %w64u: dup2(_, 1) failed: %m\n",
                    client_num);
            return 1;
        }
        if (close(new_stdin) != 0 || fclose(client_f) != 0) {
            fprintf(stderr, "client %w64u: close failed: %m\n", client_num);
            return 1;
        }

        fprintf(stderr, "client %w64u: forwarding to qrexec\n", client_num);

        execlp("qrexec-client-vm",
               "qrexec-client-vm",
               "@default",
               req,
               NULL);
        fprintf(stderr, "client %w64u: exec failed: %m\n", client_num);
        return 1;
    }
}
