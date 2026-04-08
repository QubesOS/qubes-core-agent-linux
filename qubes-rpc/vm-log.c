/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2025-2026  Piotr Bartman-Szwarc
                                      <prbartman@invisiblethingslab.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <regex.h>
#include <qubes/pure.h>

#define MAX_LINE_SIZE 4096
#define DEFAULT_PRIO LOG_INFO

// Syslog priority array (Severity 0 to 7)
const int SEV2SYSLOG_ARRAY[] = {
    LOG_EMERG,
    LOG_ALERT,
    LOG_CRIT,
    LOG_ERR,
    LOG_WARNING,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG,
};


/**
 * Extracts the syslog severity (0-7).
 * @param pri Full priority value (facility * 8 + severity)
 * @return The severity value (LOG_EMERG, LOG_ALERT, etc.)
 */
int extract_priority(int pri) {
    int severity = pri % 8;
    if (severity >= 0 && severity <= 7) {
        return SEV2SYSLOG_ARRAY[severity];
    }
    return DEFAULT_PRIO;
}

/**
 * Analyzes priority and sanitizes the input string.
 *
 * @param msg_in Untrusted log line (read-only)
 * @param msg_out Buffer for the sanitized message
 * @param msg_out_size Size of the message buffer
 * @return Syslog priority
 */
int sanitize(const char *untr_msg_in, char *msg_out, size_t msg_out_size) {
    int prio = DEFAULT_PRIO;

    // Max size for the matched priority string (up to 3 digits + NUL)
    char prio_str[4] = {0};

    regex_t regex;
    // Regex pattern: starts with '<' followed by 1-3 digits, followed by '>',
    // and then anything
    const char *pattern = "^<([0-9]{1,3})>.*$";
    const int priority_id = 1;
    regmatch_t matches[2];

    if (regcomp(&regex, pattern, REG_EXTENDED) == 0) {
        if (regexec(&regex, untr_msg_in, 2, matches, 0) == 0) {
            // Check if the priority group was matched
            if (matches[priority_id].rm_so != -1) {
                // Convert signed regoff_t difference to size_t
                long len_signed =
                        matches[priority_id].rm_eo - matches[priority_id].rm_so;

                if (len_signed > 0) {
                    size_t len = (size_t) len_signed;

                    // Comparison: size_t (len) vs size_t (sizeof)
                    if (len < sizeof(prio_str)) {
                        strncpy(prio_str,
                                untr_msg_in + matches[priority_id].rm_so, len);
                        prio_str[len] = '\0';

                        // Convert string to integer
                        int full_prio = atoi(prio_str);
                        prio = extract_priority(full_prio);
                    }
                }
            }
        }
        regfree(&regex);
    }

    // Sanitize the message and write it to msg_out
    // Cast return value to void as it is ignored right now
    (void) qubes_pure_sanitize_string_safe_for_display(
        untr_msg_in, msg_out, msg_out_size);

    return prio;
}

void handle_untrusted(const char *vm, const struct LogBackend *backend) {
    char ident[256];
    snprintf(ident, sizeof(ident), "qubes.Log(%s)", vm);

    backend->open(ident);

    char buffer[MAX_LINE_SIZE + 2];
    char trusted_msg[MAX_LINE_SIZE + 4];

    // Initial confirmation to the sender, i.e., we are ready to receive messages
    printf("OK\n");
    fflush(stdout);

    while (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Determine the actual length of the string read (before NUL)
        size_t len = strlen(buffer);

        int truncated = 0;
        // If fgets stopped due to buffer size (len >= MAX_LINE_SIZE + 1)
        // AND the last character is NOT '\n', the line was truncated.
        if (len == sizeof(buffer) - 1 && buffer[MAX_LINE_SIZE] != '\n') {
            truncated = 1;

            int c;
            while ((c = getchar()) != '\n' && c != EOF);
        }

        // Remove trailing newline and carriage return
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[--len] = '\0';
        }
        if (len > 0 && buffer[len - 1] == '\r') {
            buffer[--len] = '\0';
        }

        // Check for empty lines
        if (len == 0 && !feof(stdin) && !truncated) {
            continue;
        }

        int trusted_prio = sanitize(buffer, trusted_msg, MAX_LINE_SIZE);

        if (truncated) {
            strcat(trusted_msg, "...");
        }


        backend->write(trusted_prio, trusted_msg);

        // confrimation to the sender
        printf("OK\n");
        fflush(stdout);
    }

    backend->close();
}


int main() {
    const char *remote_domain = getenv("QREXEC_REMOTE_DOMAIN");
    if (!remote_domain) {
        fprintf(
            stderr,
            "Error: Failed to identify the source VM (QREXEC_REMOTE_DOMAIN not set).\n");
        return 1;
    }

    struct QubesSlice remote_domain_slice =
            qubes_pure_buffer_init_from_nul_terminated_string(remote_domain);
    if (qubes_pure_is_valid_qube_name(remote_domain_slice) != QUBE_NAME_OK) {
        fprintf(stderr, "Error: Invalid QREXEC_REMOTE_DOMAIN.\n");
        return 1;
    }

    (void) handle_untrusted(remote_domain);

    return 0;
}
