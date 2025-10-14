#define _GNU_SOURCE 1

#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#include "qubes-admin-authz-common.h"

int pam_sm_authenticate(pam_handle_t *pamh,
                        __attribute__((unused)) int flags,
                        int argc,
                        const char **argv) {
    bool debug = false;
    bool quiet = false;
    int rc = PAM_ABORT;
    int s = -1;

    for (int i = 0; i < argc; i += 1) {
        if (strcmp(argv[i], "debug") == 0) {
            debug = true;
        } else if (strcmp(argv[i], "quiet") == 0) {
            quiet = true;
        } else {
            pam_syslog(pamh, LOG_ERR, "unkown option: %s", argv[i]);
        }
    }

    // Only allow users in the "qubes" group to use this module.
    uid_t uid = getuid();
    if (!pam_modutil_user_in_group_uid_nam(pamh, uid, "qubes")) {
        if (debug) {
            pam_syslog(pamh, LOG_DEBUG, "uid %i not in qubes group", uid);
        }
        rc = PAM_IGNORE;
        goto ret;
    }
    if (debug) {
        pam_syslog(pamh, LOG_DEBUG, "uid %i in qubes group", uid);
    }

    // Only allow services we know it makes sense for. For example for an ssh
    // login attempt it would be a bad idea to allow authentication with this
    // module.
    const char* service = NULL;
    rc = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    if (rc != PAM_SUCCESS || service == NULL) {
        pam_syslog(pamh, LOG_CRIT, "failed to get PAM_SERVICE: %i", rc);
        rc = PAM_SYSTEM_ERR;
        goto ret;
    }
    if (!(strcmp(service, "su") == 0 ||
          strcmp(service, "su-l") == 0 ||
          strcmp(service, "sudo") == 0 ||
          strcmp(service, "sudo-i") == 0 ||
          strcmp(service, "polkit-1") == 0)) {
        if (debug) {
            pam_syslog(pamh, LOG_DEBUG, "ignoring service %s", service);
        }
        rc = PAM_IGNORE;
        goto ret;
    }
    if (debug) {
        pam_syslog(pamh, LOG_DEBUG, "handling service %s", service);
    }

    s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s == -1) {
        pam_syslog(pamh, LOG_CRIT, "failed to create socket: %i", errno);
        rc = PAM_SYSTEM_ERR;
        goto ret;
    }

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
        .sun_path = SOCKET_PATH,
    };

    if (debug) {
        pam_syslog(pamh, LOG_DEBUG, "connecting to authzd");
    }
    rc = connect(s,
                 (struct sockaddr*)&addr,
                 sizeof(addr.sun_family) + sizeof(SOCKET_PATH) - 1);
    if (rc != 0) {
        pam_syslog(pamh, LOG_ERR,
                   "failed to connect to authorization daemon: %i", errno);
        rc = PAM_AUTHINFO_UNAVAIL;
        goto ret;
    }
    if (debug) {
        pam_syslog(pamh, LOG_DEBUG, "connected");
    }

    struct ucred cred = {};
    socklen_t cred_size = sizeof(cred);
    rc = getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &cred_size);
    if (rc == -1) {
        pam_syslog(pamh, LOG_CRIT,
                   "failed to get peer credentials from socket: %i", errno);
        rc = PAM_SYSTEM_ERR;
        goto ret;
    }
    if (cred_size != sizeof(cred)) {
        pam_syslog(pamh, LOG_CRIT,
                "failed to get peer credentials from socket: unexpected size");
        rc = PAM_SYSTEM_ERR;
        goto ret;
    }
    if (debug) {
        pam_syslog(pamh, LOG_DEBUG,
                   "authz socket opened by uid=%i gid=%i pid=%i",
                   cred.uid, cred.gid, cred.pid);
    }
    if (cred.uid != 0) {
        pam_syslog(pamh, LOG_CRIT, "socket not opened by root");
        rc = PAM_SYSTEM_ERR;
        goto ret;
    }

    char res[100] = {};
    ssize_t read_ret = read(s, &res, sizeof(res) - 1);
    if (read_ret < 0) {
        pam_syslog(pamh, LOG_ERR, "failed to read from socket: %i", errno);
        rc = PAM_SYSTEM_ERR;
        goto ret;
    }

    // Since the other side is trusted this isn't strictly necessary. But it's
    // probably still nicer to ensure that we don't put unexpected bytes into
    // the log.
    for (size_t i = 0; i < sizeof(res) - 1; i += 1) {
        if (res[i] == '\0') {
            break;
        }
        if (res[i] < 0x20 || res[i] > 0x7e) {
            res[i] = '.';
        }
    }

    if (strcmp(res, "authorized") != 0) {
        pam_syslog(pamh, LOG_NOTICE, "access not authorized: %s", res);
        rc = PAM_AUTH_ERR;
        goto ret;
    }

    if (!quiet) {
        pam_syslog(pamh, LOG_INFO, "access authorized");
    }

    rc = PAM_SUCCESS;

ret:
    if (s >= 0) {
        if (close(s) == -1) {
            pam_syslog(pamh, LOG_CRIT, "failed to close socket: %i", errno);
            rc = PAM_SYSTEM_ERR;
        }
    }
    return rc;
}

int pam_sm_setcred(__attribute__((unused)) pam_handle_t *pamh,
                   __attribute__((unused)) int flags,
                   __attribute__((unused)) int argc,
                   __attribute__((unused)) const char **argv) {
    return PAM_IGNORE;
}
