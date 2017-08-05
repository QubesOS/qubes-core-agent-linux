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

#define QREXEC_FORK_SERVER_SOCKET "/var/run/qubes/qrexec-server.%s.sock"

// directory for services configuration (for example 'wait-for-session' flag)
#define QUBES_RPC_CONFIG_DIR "/etc/qubes/rpc-config"
// support only very small configuration files,
#define MAX_CONFIG_SIZE 4096

int handle_handshake(libvchan_t *ctrl);
void handle_vchan_error(const char *op);
void do_exec(const char *cmd);
/* call before fork() for service handling process (either end) */
void prepare_child_env();

pid_t handle_new_process(int type,
        int connect_domain, int connect_port,
        char *cmdline, int cmdline_len);
int handle_data_client(int type,
        int connect_domain, int connect_port,
        int stdin_fd, int stdout_fd, int stderr_fd);


struct qrexec_cmd_info {
	int type;
	int connect_domain;
	int connect_port;
	int cmdline_len;
	char cmdline[0];
};
