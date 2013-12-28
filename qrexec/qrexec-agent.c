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
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
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
    int pid; /* pid of child process handling the data */
    int fd;  /* socket to process handling the data (wait for EOF here) */
    int connect_domain;
    int connect_port;
};

int max_process_fd = -1;

/*  */
struct _connection_info connection_info[MAX_FDS];

libvchan_t *ctrl_vchan;

int trigger_fd;

int meminfo_write_started = 0;

void no_colon_in_cmd()
{
    fprintf(stderr,
            "cmdline is supposed to be in user:command form\n");
    exit(1);
}

/* Start program requested by dom0 in already prepared process
 * (stdin/stdout/stderr already set, etc)
 * Called in two cases:
 *  MSG_JUST_EXEC - from qrexec-agent-data.c:handle_new_process_common->handle_just_exec
 *  MSG_EXEC_CMDLINE - from
 *  qrexec-agent-data.c:handle_new_process_common->do_fork_exec (callback
 *  registerd with register_exec_func in init() here)
 *
 * cmd parameter came from dom0 (MSG_JUST_EXEC or MSG_EXEC_CMDLINE messages), so
 * is trusted. Even in VM-VM service request, the command here is controlled by
 * dom0 - it will be in form:
 * RPC_REQUEST_COMMAND " " service_name " " source_vm_name
 * where service_name is already validated against Qrexec RPC policy
 *
 * If dom0 sends overly long cmd, it will probably crash qrexec-agent (unless
 * process can allocate up to 4GB on both stack and heap), sorry.
 */
void do_exec(const char *cmd)
{
    char buf[strlen(QUBES_RPC_MULTIPLEXER_PATH) + strlen(cmd) - RPC_REQUEST_COMMAND_LEN + 1];
    char *realcmd = index(cmd, ':'), *user;
    if (!realcmd)
        no_colon_in_cmd();
    /* mark end of username and move to command */
    user=strndup(cmd,realcmd-cmd);
    realcmd++;
    /* ignore "nogui:" prefix in linux agent */
    if (strncmp(realcmd, NOGUI_CMD_PREFIX, NOGUI_CMD_PREFIX_LEN) == 0)
        realcmd += NOGUI_CMD_PREFIX_LEN;
    /* replace magic RPC cmd with RPC multiplexer path */
    if (strncmp(realcmd, RPC_REQUEST_COMMAND " ", RPC_REQUEST_COMMAND_LEN+1)==0) {
        strcpy(buf, QUBES_RPC_MULTIPLEXER_PATH);
        strcpy(buf + strlen(QUBES_RPC_MULTIPLEXER_PATH), realcmd + RPC_REQUEST_COMMAND_LEN);
        realcmd = buf;
    }
    signal(SIGCHLD, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);

    execl("/bin/su", "su", "-", user, "-c", realcmd, NULL);
    perror("execl");
    exit(1);
}

void handle_vchan_error(const char *op)
{
    fprintf(stderr, "Error while vchan %s, exiting\n", op);
    exit(1);
}

void init()
{
    mode_t old_umask;
    /* FIXME: This 0 is remote domain ID */
    ctrl_vchan = libvchan_server_init(0, VCHAN_BASE_PORT, 4096, 4096);
    if (!ctrl_vchan)
        handle_vchan_error("server_init");
    if (handle_handshake(ctrl_vchan) < 0)
        exit(1);
    old_umask = umask(0);
    trigger_fd = get_server_socket(QREXEC_AGENT_TRIGGER_PATH);
    umask(old_umask);
    register_exec_func(do_exec);

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

int try_fork_server(int type, int connect_domain, int connect_port,
        char *cmdline, int cmdline_len) {
    char username[cmdline_len];
    char *colon;
    char *fork_server_socket_path;
    int s, len;
    struct sockaddr_un remote;
    struct qrexec_cmd_info info;

    strncpy(username, cmdline, cmdline_len);
    colon = index(username, ':');
    if (!colon)
        return -1;
    *colon = '\0';

    if (asprintf(&fork_server_socket_path, QREXEC_FORK_SERVER_SOCKET, username) < 0) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, fork_server_socket_path,
            sizeof(remote.sun_path));
    free(fork_server_socket_path);

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if (connect(s, (struct sockaddr *) &remote, len) == -1) {
        if (errno != ECONNREFUSED && errno != ENOENT)
            perror("connect");
        close(s);
        return -1;
    }

    info.type = type;
    info.connect_domain = connect_domain;
    info.connect_port = connect_port;
    info.cmdline_len = cmdline_len-(strlen(username)+1);
    if (!write_all(s, &info, sizeof(info))) {
        perror("write");
        close(s);
        return -1;
    }
    if (!write_all(s, colon+1, info.cmdline_len)) {
        perror("write");
        close(s);
        return -1;
    }

    return s;
}


void register_vchan_connection(pid_t pid, int fd, int domain, int port)
{
    int i;

    for (i = 0; i < MAX_FDS; i++) {
        if (connection_info[i].pid == 0) {
            connection_info[i].pid = pid;
            connection_info[i].fd = fd;
            connection_info[i].connect_domain = domain;
            connection_info[i].connect_port = port;
            return;
        }
    }

    fprintf(stderr, "No free slot for child %d (connection to %d:%d)\n", pid, domain, port);
}

/* hdr parameter is received from dom0, so it is trusted */
void handle_server_exec_request(struct msg_header *hdr)
{
    struct exec_params params;
    int buf_len = hdr->len-sizeof(params);
    char buf[buf_len];
    pid_t child_agent;
    int client_fd;

    assert(hdr->len >= sizeof(params));

    if (libvchan_recv(ctrl_vchan, &params, sizeof(params)) < 0)
        handle_vchan_error("read exec params");
    if (libvchan_recv(ctrl_vchan, buf, buf_len) < 0)
        handle_vchan_error("read exec cmd");

    if ((hdr->type == MSG_EXEC_CMDLINE || hdr->type == MSG_JUST_EXEC) &&
            !strstr(buf, ":nogui:")) {
        int child_socket = try_fork_server(hdr->type,
                params.connect_domain, params.connect_port,
                buf, buf_len);
        if (child_socket >= 0) {
            register_vchan_connection(-1, child_socket,
                    params.connect_domain, params.connect_port);
            return;
        }
    }
    if (hdr->type == MSG_SERVICE_CONNECT && sscanf(buf, "SOCKET%d", &client_fd)) {
        /* FIXME: Maybe add some check if client_fd is really FD to some
         * qrexec-client-vm process; but this data comes from qrexec-daemon
         * (which sends back what it got from us earlier), so it isn't critical.
         */
        if (write(client_fd, &params, sizeof(params)) < 0) {
            /* ignore */
        }
        /* No need to send request_id (buf) - the client don't need it, there
         * is only meaningless (for the client) socket FD */
        /* Register connection even if there was an error sending params to
         * qrexec-client-vm. This way the mainloop will clean the things up
         * (close socket, send MSG_CONNECTION_TERMINATED) when qrexec-client-vm
         * will close the socket (terminate itself). */
        register_vchan_connection(-1, client_fd,
                params.connect_domain, params.connect_port);
        return;
    }

    /* No fork server case */
    child_agent = handle_new_process(hdr->type,
            params.connect_domain, params.connect_port,
            buf, buf_len);

    register_vchan_connection(child_agent, -1,
            params.connect_domain, params.connect_port);
}

void handle_service_refused(struct msg_header *hdr)
{
    struct service_params params;
    int socket_fd;

    if (hdr->len != sizeof(params)) {
        fprintf(stderr, "Invalid msg 0x%x length (%d)\n", MSG_SERVICE_REFUSED, hdr->len);
        exit(1);
    }

    if (libvchan_recv(ctrl_vchan, &params, sizeof(params)) < 0)
        handle_vchan_error("read exec params");

    if (sscanf(params.ident, "SOCKET%d", &socket_fd))
        close(socket_fd);
    else
        fprintf(stderr, "Received REFUSED for unknown service request '%s'\n", params.ident);
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

void release_connection(int id) {
    struct msg_header hdr;
    struct exec_params params;

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

void reap_children()
{
    int status;
    int pid;
    int id;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        id = find_connection(pid);
        if (id < 0)
            continue;
        release_connection(id);
    }
    child_exited = 0;
}

int fill_fds_for_select(fd_set * rdset, fd_set * wrset)
{
    int max = -1;
    int i;
    FD_ZERO(rdset);
    FD_ZERO(wrset);

    FD_SET(trigger_fd, rdset);
    if (trigger_fd > max)
        max = trigger_fd;

    for (i = 0; i < MAX_FDS; i++) {
        if (connection_info[i].pid != 0 && connection_info[i].fd != -1) {
            FD_SET(connection_info[i].fd, rdset);
            if (connection_info[i].fd > max)
                max = connection_info[i].fd;
        }
    }
    return max;
}

void handle_trigger_io()
{
    struct msg_header hdr;
    struct trigger_service_params params;
    int ret;
    int client_fd;

    client_fd = do_accept(trigger_fd);
    if (client_fd < 0)
        return;
    hdr.len = sizeof(params);
    ret = read(client_fd, &params, sizeof(params));
    if (ret == sizeof(params)) {
        hdr.type = MSG_TRIGGER_SERVICE;
        snprintf(params.request_id.ident, sizeof(params.request_id), "SOCKET%d", client_fd);
        if (libvchan_send(ctrl_vchan, &hdr, sizeof(hdr)) < 0)
            handle_vchan_error("write hdr");
        if (libvchan_send(ctrl_vchan, &params, sizeof(params)) < 0)
            handle_vchan_error("write params");
    }
    if (ret <= 0) {
        close(client_fd);
    }
    /* do not close client_fd - we'll need it to send the connection details
     * later (when dom0 accepts the request) */
}

void handle_terminated_fork_client(fd_set *rdset) {
    int i, ret;
    char buf[2];

    for (i = 0; i < MAX_FDS; i++) {
        if (connection_info[i].pid && connection_info[i].fd >= 0 &&
                FD_ISSET(connection_info[i].fd, rdset)) {
            ret = read(connection_info[i].fd, buf, sizeof(buf));
            if (ret == 0 || (ret == -1 && errno == ECONNRESET)) {
                close(connection_info[i].fd);
                release_connection(i);
            } else {
                fprintf(stderr, "Unexpected read on fork-server connection: %d(%s)\n", ret, strerror(errno));
                close(connection_info[i].fd);
                release_connection(i);
            }
        }
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

        while (libvchan_data_ready(ctrl_vchan))
            handle_server_cmd();

        if (FD_ISSET(trigger_fd, &rdset))
            handle_trigger_io();

        handle_terminated_fork_client(&rdset);
    }
}
