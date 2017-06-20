/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "libqrexec-utils.h"
#include "qrexec.h"
#include "qrexec-agent.h"

void handle_vchan_error(const char *op)
{
    fprintf(stderr, "Error while vchan %s, exiting\n", op);
    exit(1);
}

void do_exec(const char *cmd __attribute__((__unused__))) {
    fprintf(stderr, "BUG: do_exec function shouldn't be called!\n");
    exit(1);
}

int connect_unix_socket(char *path)
{
    int s, len;
    struct sockaddr_un remote;

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, path,
            sizeof(remote.sun_path));
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if (connect(s, (struct sockaddr *) &remote, len) == -1) {
        perror("connect");
        exit(1);
    }
    return s;
}

char *get_program_name(char *prog)
{
    char *basename = rindex(prog, '/');
    if (basename)
        return basename + 1;
    else
        return prog;
}

int main(int argc, char **argv)
{
    int trigger_fd;
    struct trigger_service_params params;
    struct exec_params exec_params;
    int ret, i;
    int start_local_process = 0;
    char *abs_exec_path;
    pid_t child_pid = 0;
    int inpipe[2], outpipe[2];

    if (argc < 3) {
        fprintf(stderr,
                "usage: %s target_vmname program_ident [local_program [local program arguments]]\n",
                argv[0]);
        exit(1);
    }
    if (argc > 3) {
        start_local_process = 1;
    }

    trigger_fd = connect_unix_socket(QREXEC_AGENT_TRIGGER_PATH);

    memset(&params, 0, sizeof(params));
    strncpy(params.service_name, argv[2], sizeof(params.service_name));
    strncpy(params.target_domain, argv[1],
            sizeof(params.target_domain));
    snprintf(params.request_id.ident,
            sizeof(params.request_id.ident), "SOCKET");

    if (write(trigger_fd, &params, sizeof(params)) < 0) {
        perror("write to agent");
        exit(1);
    }
    ret = read(trigger_fd, &exec_params, sizeof(exec_params));
    if (ret == 0) {
        fprintf(stderr, "Request refused\n");
        exit(126);
    }
    if (ret < 0 || ret != sizeof(exec_params)) {
        perror("read");
        exit(1);
    }

    if (start_local_process) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, inpipe) ||
                socketpair(AF_UNIX, SOCK_STREAM, 0, outpipe)) {
            perror("socketpair");
            exit(1);
        }
        prepare_child_env();

        switch (child_pid = fork()) {
            case -1:
                perror("fork");
                exit(-1);
            case 0:
                close(inpipe[1]);
                close(outpipe[0]);
                close(trigger_fd);
                for (i = 0; i < 3; i++) {
                    if (i != 2 || getenv("PASS_LOCAL_STDERR")) {
                        char *env;
                        if (asprintf(&env, "SAVED_FD_%d=%d", i, dup(i)) < 0) {
                            perror("prepare SAVED_FD_");
                            exit(1);
                        }
                        putenv(env);
                    }
                }

                dup2(inpipe[0], 0);
                dup2(outpipe[1], 1);
                close(inpipe[0]);
                close(outpipe[1]);

                abs_exec_path = strdup(argv[3]);
                argv[3] = get_program_name(argv[3]);
                execv(abs_exec_path, argv + 3);
                perror("execv");
                exit(-1);
        }
        close(inpipe[0]);
        close(outpipe[1]);

        ret = handle_data_client(MSG_SERVICE_CONNECT,
                exec_params.connect_domain, exec_params.connect_port,
                inpipe[1], outpipe[0], -1);
    } else {
        ret = handle_data_client(MSG_SERVICE_CONNECT,
                exec_params.connect_domain, exec_params.connect_port,
                1, 0, -1);
    }

    close(trigger_fd);
    if (start_local_process) {
        if (waitpid(child_pid, &i, 0) != -1) {
            if (WIFSIGNALED(i))
                ret = 128 + WTERMSIG(i);
            else
                ret = WEXITSTATUS(i);
        } else {
            perror("wait for local process");
        }
    }

    return ret;
}
