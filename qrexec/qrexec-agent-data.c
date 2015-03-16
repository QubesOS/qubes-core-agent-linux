/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2013  Marek Marczykowski-Górecki  <marmarek@invisiblethingslab.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <libvchan.h>
#include <assert.h>
#include "qrexec.h"
#include "libqrexec-utils.h"
#include "qrexec-agent.h"

#define VCHAN_BUFFER_SIZE 65536

static volatile int child_exited;
static volatile int stdio_socket_requested;
int stdout_msg_type = MSG_DATA_STDOUT;
pid_t child_process_pid;
int remote_process_status = 0;

static void sigchld_handler(int __attribute__((__unused__))x)
{
    child_exited = 1;
    signal(SIGCHLD, sigchld_handler);
}

static void sigusr1_handler(int __attribute__((__unused__))x)
{
    stdio_socket_requested = 1;
    signal(SIGUSR1, SIG_IGN);
}

int handle_handshake(libvchan_t *ctrl)
{
    struct msg_header hdr;
    struct peer_info info;

    /* send own HELLO */
    hdr.type = MSG_HELLO;
    hdr.len = sizeof(info);
    info.version = QREXEC_PROTOCOL_VERSION;

    if (libvchan_send(ctrl, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        fprintf(stderr, "Failed to send HELLO hdr to agent\n");
        return -1;
    }

    if (libvchan_send(ctrl, &info, sizeof(info)) != sizeof(info)) {
        fprintf(stderr, "Failed to send HELLO hdr to agent\n");
        return -1;
    }

    /* receive MSG_HELLO from remote */
    if (libvchan_recv(ctrl, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        fprintf(stderr, "Failed to read agent HELLO hdr\n");
        return -1;
    }

    if (hdr.type != MSG_HELLO || hdr.len != sizeof(info)) {
        fprintf(stderr, "Invalid HELLO packet received: type %d, len %d\n", hdr.type, hdr.len);
        return -1;
    }

    if (libvchan_recv(ctrl, &info, sizeof(info)) != sizeof(info)) {
        fprintf(stderr, "Failed to read agent HELLO body\n");
        return -1;
    }

    if (info.version != QREXEC_PROTOCOL_VERSION) {
        fprintf(stderr, "Incompatible agent protocol version (remote %d, local %d)\n", info.version, QREXEC_PROTOCOL_VERSION);
        return -1;
    }


    return 0;
}


int handle_just_exec(char *cmdline)
{
    int fdn, pid;

    switch (pid = fork()) {
        case -1:
            perror("fork");
            return -1;
        case 0:
            fdn = open("/dev/null", O_RDWR);
            fix_fds(fdn, fdn, fdn);
            do_exec(cmdline);
            perror("execl");
            exit(1);
        default:;
    }
    fprintf(stderr, "executed (nowait) %s pid %d\n", cmdline, pid);
    return 0;
}

void send_exit_code(libvchan_t *data_vchan, int status)
{
    struct msg_header hdr;
    hdr.type = MSG_DATA_EXIT_CODE;
    hdr.len = sizeof(status);
    if (libvchan_send(data_vchan, &hdr, sizeof(hdr)) < 0)
        handle_vchan_error("write hdr");
    if (libvchan_send(data_vchan, &status, sizeof(status)) < 0)
        handle_vchan_error("write status");
    fprintf(stderr, "send exit code %d\n", status);
}

/* handle data from specified FD and send over vchan link
 * Return:
 *  -1 - vchan error occurred
 *  0 - EOF received, do not attempt to access this FD again
 *  1 - some data processed, call it again when buffer space and more data
 *      available
 */
int handle_input(libvchan_t *vchan, int fd, int msg_type)
{
	char buf[MAX_DATA_CHUNK];
    int len;
    struct msg_header hdr;

    hdr.type = msg_type;
    while (libvchan_buffer_space(vchan) > (int)sizeof(struct msg_header)) {
        len = libvchan_buffer_space(vchan)-sizeof(struct msg_header);
        if (len > (int)sizeof(buf))
            len = sizeof(buf);
        len = read(fd, buf, len);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 1;
            else
                return -1;
        }
        hdr.len = len;
        if (libvchan_send(vchan, &hdr, sizeof(hdr)) < 0)
            return -1;

        if (len && !write_vchan_all(vchan, buf, len))
            return -1;

        if (len == 0) {
            if (shutdown(fd, SHUT_RD) < 0) {
                if (errno == ENOTSOCK)
                    close(fd);
            }
            return 0;
        }
    }
    return 1;
}

/* handle data from vchan and send it to specified FD
 * Return:
 *  -2 - remote process terminated, do not send more data to it
 *       in this case "status" will be set
 *  -1 - vchan error occurred
 *  0 - EOF received, do not attempt to access this FD again
 *  1 - some data processed, call it again when buffer space and more data
 *      available
 */

int handle_remote_data(libvchan_t *data_vchan, int stdin_fd, int *status)
{
	struct msg_header hdr;
    char buf[MAX_DATA_CHUNK];

    /* TODO: set stdin_fd to non-blocking mode and handle its buffering */
    while (libvchan_data_ready(data_vchan) > 0) {
        if (libvchan_recv(data_vchan, &hdr, sizeof(hdr)) < 0)
            return -1;
        if (hdr.len > MAX_DATA_CHUNK) {
            fprintf(stderr, "Too big data chunk received: %d > %d\n",
                    hdr.len, MAX_DATA_CHUNK);
            return -1;
        }
        if (!read_vchan_all(data_vchan, buf, hdr.len))
            return -1;

        switch (hdr.type) {
            /* handle both directions because this can be either server or client
             * of VM-VM connection */
            case MSG_DATA_STDIN:
            case MSG_DATA_STDOUT:
                if (stdin_fd < 0)
                    /* discard the data */
                    continue;
                if (hdr.len == 0) {
                    if (shutdown(stdin_fd, SHUT_WR) < 0) {
                        if (errno == ENOTSOCK)
                            close(stdin_fd);
                    }
                    stdin_fd = -1;
                    return 0;
                } else {
                    /* FIXME: use buffered write here to prevent deadlock */
                    if (!write_all(stdin_fd, buf, hdr.len)) {
                        if (errno == EPIPE || errno == ECONNRESET) {
                            if (shutdown(stdin_fd, SHUT_WR) < 0) {
                                if (errno == ENOTSOCK)
                                    close(stdin_fd);
                            }
                            stdin_fd = -1;
                        } else {
                            perror("write");
                        }
                        return 0;
                    }
                }
                break;
            case MSG_DATA_STDERR:
                /* stderr of remote service, log locally */
                if (!write_all(2, buf, hdr.len)) {
                    perror("write");
                    /* only log the error */
                }
                break;
            case MSG_DATA_EXIT_CODE:
                /* remote process exited, so there is no sense to send any data
                 * to it */
                if (hdr.len < sizeof(*status))
                    *status = 255;
                else
                    memcpy(status, buf, sizeof(*status));
                return -2;
        }
    }
    return 1;
}

int process_child_io(libvchan_t *data_vchan,
        int stdin_fd, int stdout_fd, int stderr_fd)
{
    fd_set rdset, wrset;
    int vchan_fd;
    sigset_t selectmask;
    int child_process_status = -1;
    int remote_process_status = -1;
    int ret, max_fd;
    struct timespec zero_timeout = { 0, 0 };

    sigemptyset(&selectmask);
    sigaddset(&selectmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &selectmask, NULL);
    sigemptyset(&selectmask);

    set_nonblock(stdout_fd);
    set_nonblock(stderr_fd);

    while (1) {
        if (child_exited) {
            pid_t pid;
            int status;
            while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
                if (pid == child_process_pid) {
                    child_process_status = WEXITSTATUS(status);
                    if (stdin_fd >= 0) {
                        if (shutdown(stdin_fd, SHUT_WR) < 0) {
                            if (errno == ENOTSOCK)
                                close(stdin_fd);
                        }
                        stdin_fd = -1;
                    }
                }
            }
            child_exited = 0;
        }

        /* if all done, exit the loop */
        if ((!child_process_pid || child_process_status > -1) &&
                (child_process_pid || remote_process_status > -1) &&
                stdin_fd == -1 && stdout_fd == -1 && stderr_fd == -1) {
            if (child_process_status > -1) {
                send_exit_code(data_vchan, child_process_status);
            }
            break;
        }
        /* also if vchan is disconnected (and we processed all the data), there
         * is no sense of processing further data */
        if (!libvchan_data_ready(data_vchan) && !libvchan_is_open(data_vchan)) {
            if (child_process_pid)
                return remote_process_status;
            else
                return child_process_status;
        }
        /* child signaled desire to use single socket for both stdin and stdout */
        if (stdio_socket_requested) {
            if (stdout_fd != -1)
                close(stdout_fd);
            stdout_fd = stdin_fd;
            stdio_socket_requested = 0;
        }
        /* otherwise handle the events */

        FD_ZERO(&rdset);
        FD_ZERO(&wrset);
        max_fd = -1;
        vchan_fd = libvchan_fd_for_select(data_vchan);
        if (libvchan_buffer_space(data_vchan) > (int)sizeof(struct msg_header)) {
            if (stdout_fd >= 0) {
                FD_SET(stdout_fd, &rdset);
                if (stdout_fd > max_fd)
                    max_fd = stdout_fd;
            }
            if (stderr_fd >= 0) {
                FD_SET(stderr_fd, &rdset);
                if (stderr_fd > max_fd)
                    max_fd = stderr_fd;
            }
        }
        FD_SET(vchan_fd, &rdset);
        if (vchan_fd > max_fd)
            max_fd = vchan_fd;

        if (libvchan_data_ready(data_vchan) > 0) {
            /* check for other FDs, but exit immediately */
            ret = pselect(max_fd + 1, &rdset, &wrset, NULL, &zero_timeout, &selectmask);
        } else
            ret = pselect(max_fd + 1, &rdset, &wrset, NULL, NULL, &selectmask);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            else {
                perror("pselect");
                /* TODO */
                break;
            }
        }

        /* clear event pending flag */
        if (FD_ISSET(vchan_fd, &rdset)) {
            if (libvchan_wait(data_vchan) < 0)
                handle_vchan_error("wait");
        }

        if (stdout_fd >= 0 && FD_ISSET(stdout_fd, &rdset)) {
            switch (handle_input(data_vchan, stdout_fd, stdout_msg_type)) {
                case -1:
                    handle_vchan_error("send");
                    break;
                case 0:
                    stdout_fd = -1;
                    break;
            }
        }
        if (stderr_fd >= 0 && FD_ISSET(stderr_fd, &rdset)) {
            switch (handle_input(data_vchan, stderr_fd, MSG_DATA_STDERR)) {
                case -1:
                    handle_vchan_error("send");
                    break;
                case 0:
                    stderr_fd = -1;
                    break;
            }
        }
        /* handle_remote_data will check if any data is available */
        switch (handle_remote_data(data_vchan, stdin_fd, &remote_process_status)) {
            case -1:
                handle_vchan_error("read");
                break;
            case 0:
                stdin_fd = -1;
                break;
            case -2:
                /* remote process exited, no sense in sending more data to it */
                if (shutdown(stdout_fd, SHUT_RD) < 0) {
                    if (errno == ENOTSOCK)
                        close(stdout_fd);
                }
                stdout_fd = -1;
                close(stderr_fd);
                stderr_fd = -1;
                /* if we do not care for any local process, return remote process code */
                if (child_process_pid == 0)
                    return remote_process_status;
                break;
        }
    }
    return child_process_status;
}

/* Behaviour depends on type parameter:
 *  MSG_SERVICE_CONNECT - create vchan server, pass the data to/from given FDs
 *    (stdin_fd, stdout_fd, stderr_fd), then return remote process exit code
 *  MSG_JUST_EXEC - connect to vchan server, fork+exec process given by cmdline
 *    parameter, send artificial exit code "0" (local process can still be
 *    running), then return 0
 *  MSG_EXEC_CMDLINE - connect to vchan server, fork+exec process given by
 *    cmdline parameter, pass the data to/from that process, then return local
 *    process exit code
 */
int handle_new_process_common(int type, int connect_domain, int connect_port,
                char *cmdline, int cmdline_len, /* MSG_JUST_EXEC and MSG_EXEC_CMDLINE */
                int stdin_fd, int stdout_fd, int stderr_fd /* MSG_SERVICE_CONNECT */)
{
    libvchan_t *data_vchan;
    int exit_code = 0;
    pid_t pid;
    char pid_s[10];

    if (type != MSG_SERVICE_CONNECT) {
        assert(cmdline != NULL);
        cmdline[cmdline_len-1] = 0;
    }

    if (type == MSG_SERVICE_CONNECT) {
        data_vchan = libvchan_server_init(connect_domain, connect_port,
                VCHAN_BUFFER_SIZE, VCHAN_BUFFER_SIZE);
        if (data_vchan)
            libvchan_wait(data_vchan);
    } else {
        data_vchan = libvchan_client_init(connect_domain, connect_port);
    }
    if (!data_vchan) {
        fprintf(stderr, "Data vchan connection failed\n");
        exit(1);
    }
    handle_handshake(data_vchan);

    signal(SIGCHLD, sigchld_handler);
    signal(SIGUSR1, sigusr1_handler);
    snprintf(pid_s, sizeof(pid_s), "%d", getpid());
    setenv("QREXEC_AGENT_PID", pid_s, 1);
    /* TODO: use setresuid to allow child process to actually send the signal? */

    switch (type) {
        case MSG_JUST_EXEC:
            send_exit_code(data_vchan, handle_just_exec(cmdline));
            break;
        case MSG_EXEC_CMDLINE:
            do_fork_exec(cmdline, &pid, &stdin_fd, &stdout_fd, &stderr_fd);
            fprintf(stderr, "executed %s pid %d\n", cmdline, pid);
            child_process_pid = pid;
            exit_code = process_child_io(data_vchan, stdin_fd, stdout_fd, stderr_fd);
            fprintf(stderr, "pid %d exited with %d\n", pid, exit_code);
            break;
        case MSG_SERVICE_CONNECT:
            child_process_pid = 0;
            stdout_msg_type = MSG_DATA_STDIN;
            exit_code = process_child_io(data_vchan, stdin_fd, stdout_fd, stderr_fd);
            break;
    }
    libvchan_close(data_vchan);
    return exit_code;
}

/* Returns PID of data processing process */
pid_t handle_new_process(int type, int connect_domain, int connect_port,
        char *cmdline, int cmdline_len)
{
    int exit_code;
    pid_t pid;
    assert(type != MSG_SERVICE_CONNECT);

    switch (pid=fork()){
        case -1:
            perror("fork");
            return -1;
        case 0:
            break;
        default:
            return pid;
    }

    /* child process */
    exit_code = handle_new_process_common(type, connect_domain, connect_port,
            cmdline, cmdline_len,
            -1, -1, -1);

    exit(exit_code);
    /* suppress warning */
    return 0;
}

/* Returns exit code of remote process */
int handle_data_client(int type, int connect_domain, int connect_port,
                int stdin_fd, int stdout_fd, int stderr_fd)
{
    int exit_code;

    assert(type == MSG_SERVICE_CONNECT);

    exit_code = handle_new_process_common(type, connect_domain, connect_port,
            NULL, 0, stdin_fd, stdout_fd, stderr_fd);
    return exit_code;
}
