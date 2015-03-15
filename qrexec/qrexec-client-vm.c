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
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "qrexec.h"
int connect_unix_socket()
{
    int s, len;
    struct sockaddr_un remote;

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, QREXEC_AGENT_FDPASS_PATH,
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

/* Returns:
 *  0  - ok
 *  -1 - EOF, FDs closed
 *  -2 - error, already reported, break the loop
 */
static int handle_fd_data(int src, int dst) {
    char buf[4096];
    int buf_len, len, ret;

    ret = read(src, buf, sizeof(buf));
    if (ret == -1) {
        perror("read");
        return -2;
    }
    if (ret == 0) {
        close(src);
        close(dst);
        return -1;
    } else {
        len = 0;
        buf_len = ret;
        while (len < buf_len) {
            ret = write(dst, buf, ret);
            if (ret == -1) {
                if (errno == ECONNRESET || errno == EPIPE) {
                    close(src);
                    close(dst);
                    return -1;
                } else
                    return -2;
            } else
                len += ret;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    int trigger_fd;
    struct trigger_connect_params params;
    int local_fd[3], remote_fd[3];
    int i;
    int exec_local_process = 0;
    char *abs_exec_path;

    if (argc < 3) {
        fprintf(stderr,
                "usage: %s target_vmname program_ident [local_program [local program arguments]]\n",
                argv[0]);
        exit(1);
    }
    if (argc > 3)
        exec_local_process = 1;

    trigger_fd = open(QREXEC_AGENT_TRIGGER_PATH, O_WRONLY);
    if (trigger_fd < 0) {
        perror("open " QREXEC_AGENT_TRIGGER_PATH);
        exit(1);
    }

    for (i = 0; i < 3; i++) {
        local_fd[i] = connect_unix_socket();
        if (read(local_fd[i], &remote_fd[i], sizeof(remote_fd[i])) != sizeof(remote_fd[i])) {
            perror("read client fd");
            exit(1);
        }
        if (exec_local_process) {
            if (i != 2 || getenv("PASS_LOCAL_STDERR")) {
                char *env;
                if (asprintf(&env, "SAVED_FD_%d=%d", i, dup(i)) < 0) {
                    perror("prepare SAVED_FD_");
                    exit(1);
                }
                putenv(env);
                dup2(local_fd[i], i);
                close(local_fd[i]);
            } else
                close(local_fd[i]);
        }
    }

    memset(&params, 0, sizeof(params));
    strncpy(params.exec_index, argv[2], sizeof(params.exec_index));
    strncpy(params.target_vmname, argv[1],
        sizeof(params.target_vmname));
    snprintf(params.process_fds.ident,
         sizeof(params.process_fds.ident), "%d %d %d",
         remote_fd[0], remote_fd[1], remote_fd[2]);

    if (write(trigger_fd, &params, sizeof(params)) < 0) {
        if (!getenv("PASS_LOCAL_STDERR"))
            perror("write to agent");
        exit(1);
    }

    close(trigger_fd);

    if (exec_local_process) {
        abs_exec_path = strdup(argv[3]);
        argv[3] = get_program_name(argv[3]);
        execv(abs_exec_path, argv + 3);
        perror("execv");
        return 1;
    } else {
        fd_set rd_set;
        int ret, max_fd;

        while (local_fd[0] > 0 || local_fd[1] > 0) {
            FD_ZERO(&rd_set);
            max_fd = 0;
            if (local_fd[1] > 0) {
                FD_SET(0, &rd_set);
            }
            if (local_fd[0] > 0) {
                FD_SET(local_fd[0], &rd_set);
                max_fd = local_fd[0];
            }
            ret = select(max_fd+1, &rd_set, NULL, NULL, NULL);
            if (ret == -1) {
                perror("select");
                break;
            }
            if (FD_ISSET(0, &rd_set)) {
                switch (handle_fd_data(0, local_fd[1])) {
                    case -1:
                        local_fd[1] = -1;
                        break;
                    case -2:
                        exit(1);
                }
            }
            if (FD_ISSET(local_fd[0], &rd_set)) {
                switch (handle_fd_data(local_fd[0], 1)) {
                    case -1:
                        local_fd[0] = -1;
                        break;
                    case -2:
                        exit(1);
                }
            }
        }
    }
    return 0;
}
