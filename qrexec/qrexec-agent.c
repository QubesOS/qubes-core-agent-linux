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

#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <assert.h>
#include "qrexec.h"
#include <libvchan.h>
#include "libqrexec-utils.h"
#include "qrexec-agent.h"

struct _connection_info {
    int pid;
    int connect_domain;
    int connect_port;
};

int max_process_fd = -1;

/*  */
struct _connection_info connection_info[MAX_FDS];

libvchan_t *ctrl_vchan;

int trigger_fd;
int passfd_socket;

int meminfo_write_started = 0;

void handle_vchan_error(const char *op)
{
    fprintf(stderr, "Error while vchan %s, exiting\n", op);
    exit(1);
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

void init()
{
    /* FIXME: This 0 is remote domain ID */
    ctrl_vchan = libvchan_server_init(0, VCHAN_BASE_PORT, 4096, 4096);
    if (!ctrl_vchan)
        handle_vchan_error("server_init");
    if (handle_handshake(ctrl_vchan) < 0)
        exit(1);
    umask(0);
    mkfifo(QREXEC_AGENT_TRIGGER_PATH, 0666);
    passfd_socket = get_server_socket(QREXEC_AGENT_FDPASS_PATH);
    umask(077);
    trigger_fd =
        open(QREXEC_AGENT_TRIGGER_PATH, O_RDONLY | O_NONBLOCK);

    /* wait for qrexec daemon */
    while (!libvchan_is_open(ctrl_vchan))
        libvchan_wait(ctrl_vchan);
}

void wake_meminfo_writer()
{
    FILE *f;
    int pid;

    if (meminfo_write_started)
        /* wake meminfo-writer only once */
        return;

    f = fopen(MEMINFO_WRITER_PIDFILE, "r");
    if (f == NULL) {
        /* no meminfo-writer found, ignoring */
        return;
    }
    if (fscanf(f, "%d", &pid) < 1) {
        fclose(f);
        /* no meminfo-writer found, ignoring */
        return;
    }

    fclose(f);
    if (pid <= 1 || pid > 0xffff) {
        /* check within acceptable range */
        return;
    }
    if (kill(pid, SIGUSR1) < 0) {
        /* Can't send signal */
        return;
    }
    meminfo_write_started = 1;
}

void register_vchan_connection(pid_t pid, int domain, int port)
{
    int i;

    for (i = 0; i < MAX_FDS; i++) {
        if (connection_info[i].pid == 0) {
            connection_info[i].pid = pid;
            connection_info[i].connect_domain = domain;
            connection_info[i].connect_port = port;
            return;
        }
    }

    fprintf(stderr, "No free slot for child %d (connection to %d:%d)\n", pid, domain, port);
}

void handle_server_exec_request(struct msg_header *hdr)
{
    struct exec_params params;
    char buf[hdr->len-sizeof(params)];
    pid_t child_agent;

    assert(hdr->len >= sizeof(params));

    if (libvchan_recv(ctrl_vchan, &params, sizeof(params)) < 0)
        handle_vchan_error("read exec params");
    if (libvchan_recv(ctrl_vchan, buf, hdr->len-sizeof(params)) < 0)
        handle_vchan_error("read exec cmd");

    child_agent = handle_new_process(hdr->type,
            params.connect_domain, params.connect_port,
            buf, hdr->len-sizeof(params));

    register_vchan_connection(child_agent,
            params.connect_domain, params.connect_port);
}

void handle_service_refused(struct msg_header *hdr)
{
    struct service_params params;
    int stdin_fd, stdout_fd, stderr_fd;

    if (hdr->len != sizeof(params)) {
        fprintf(stderr, "Invalid msg 0x%x length (%d)\n", MSG_SERVICE_REFUSED, hdr->len);
        exit(1);
    }

    if (libvchan_recv(ctrl_vchan, &params, sizeof(params)) < 0)
        handle_vchan_error("read exec params");

    sscanf(params.ident, "%d %d %d", &stdin_fd, &stdout_fd, &stderr_fd);
    /* TODO: send some signal? some response? */
    close(stdin_fd);
    close(stdout_fd);
    close(stderr_fd);
}

void handle_server_cmd()
{
    struct msg_header s_hdr;

    if (libvchan_recv(ctrl_vchan, &s_hdr, sizeof(s_hdr)) < 0)
        handle_vchan_error("read s_hdr");

    //      fprintf(stderr, "got %x %x %x\n", s_hdr.type, s_hdr.client_id,
    //              s_hdr.len);

    switch (s_hdr.type) {
        case MSG_EXEC_CMDLINE:
        case MSG_JUST_EXEC:
        case MSG_SERVICE_CONNECT:
            wake_meminfo_writer();
            handle_server_exec_request(&s_hdr);
            break;
        case MSG_SERVICE_REFUSED:
            handle_service_refused(&s_hdr);
            break;
        default:
            fprintf(stderr, "msg type from daemon is %d ?\n",
                    s_hdr.type);
            exit(1);
    }
}

volatile int child_exited;

void sigchld_handler(int x __attribute__((__unused__)))
{
    child_exited = 1;
    signal(SIGCHLD, sigchld_handler);
}

int find_connection(int pid)
{
    int i;
    for (i = 0; i < MAX_FDS; i++)
        if (connection_info[i].pid == pid)
            return i;
    return -1;
}


void reap_children()
{
    int status;
    int pid;
    int id;
    struct msg_header hdr;
    struct exec_params params;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        id = find_connection(pid);
        if (id < 0)
            continue;
        hdr.type = MSG_CONNECTION_TERMINATED;
        hdr.len = sizeof(struct exec_params);
        params.connect_domain = connection_info[id].connect_domain;
        params.connect_port = connection_info[id].connect_port;
        if (libvchan_send(ctrl_vchan, &hdr, sizeof(hdr)) < 0)
            handle_vchan_error("send");
        if (libvchan_send(ctrl_vchan, &params, sizeof(params)) < 0)
            handle_vchan_error("send");
        connection_info[id].pid = 0;
    }
    child_exited = 0;
}

int fill_fds_for_select(fd_set * rdset, fd_set * wrset)
{
    int max = -1;
    FD_ZERO(rdset);
    FD_ZERO(wrset);

    FD_SET(trigger_fd, rdset);
    if (trigger_fd > max)
        max = trigger_fd;
    FD_SET(passfd_socket, rdset);
    if (passfd_socket > max)
        max = passfd_socket;
    return max;
}

void handle_new_passfd()
{
    int fd = do_accept(passfd_socket);
    if (fd >= MAX_FDS) {
        fprintf(stderr, "too many clients ?\n");
        exit(1);
    }
    // let client know what fd has been allocated
    if (write(fd, &fd, sizeof(fd)) != sizeof(fd)) {
        perror("write to client");
    }
}

void handle_trigger_io()
{
    struct msg_header hdr;
    struct trigger_service_params params;
    int ret;

    hdr.len = sizeof(params);
    ret = read(trigger_fd, &params, sizeof(params));
    if (ret == sizeof(params)) {
        hdr.type = MSG_TRIGGER_SERVICE;
        if (libvchan_send(ctrl_vchan, &hdr, sizeof(hdr)) < 0)
            handle_vchan_error("write hdr");
        if (libvchan_send(ctrl_vchan, &params, sizeof(params)) < 0)
            handle_vchan_error("write params");
    }
    // trigger_fd is nonblock - so no need to reopen
    // not really, need to reopen at EOF
    if (ret <= 0) {
        close(trigger_fd);
        trigger_fd =
            open(QREXEC_AGENT_TRIGGER_PATH, O_RDONLY | O_NONBLOCK);
    }
}

int main()
{
    fd_set rdset, wrset;
    int max;
    sigset_t chld_set;

    init();
    signal(SIGCHLD, sigchld_handler);
    signal(SIGPIPE, SIG_IGN);
    sigemptyset(&chld_set);
    sigaddset(&chld_set, SIGCHLD);


    for (;;) {
        sigprocmask(SIG_BLOCK, &chld_set, NULL);
        if (child_exited)
            reap_children();
        max = fill_fds_for_select(&rdset, &wrset);
        if (libvchan_buffer_space(ctrl_vchan) <=
                (int)sizeof(struct msg_header))
            FD_ZERO(&rdset);

        wait_for_vchan_or_argfd(ctrl_vchan, max, &rdset, &wrset);
        sigprocmask(SIG_UNBLOCK, &chld_set, NULL);

        if (FD_ISSET(passfd_socket, &rdset))
            handle_new_passfd();

        while (libvchan_data_ready(ctrl_vchan))
            handle_server_cmd();

        if (FD_ISSET(trigger_fd, &rdset))
            handle_trigger_io();
    }
}
