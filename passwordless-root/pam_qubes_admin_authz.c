#define _GNU_SOURCE 1

#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>
#include <stdio.h>

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
    const char* allowed_group = NULL;
    const char* allowed_services = NULL;
    int rc = PAM_ABORT;
    int s = -1;
    FILE* sf = NULL;

    for (int i = 0; i < argc; i += 1) {
        if (strcmp(argv[i], "debug") == 0) {
            debug = true;
        } else if (strcmp(argv[i], "quiet") == 0) {
            quiet = true;
        } else if (strncmp(argv[i], "group=", 6) == 0) {
            allowed_group = &argv[i][6];
            if (strlen(allowed_group) == 0) {
                pam_syslog(pamh, LOG_ERR, "missing value for 'group' option");
                rc = PAM_SERVICE_ERR;
                goto ret;
            }
        } else if (strncmp(argv[i], "services=", 9) == 0) {
            allowed_services = &argv[i][9];
        } else {
            pam_syslog(pamh, LOG_ERR, "unknown option: %s", argv[i]);
            // Ignore it, to make it easier to add new options in the future.
        }
    }

    if (allowed_group == NULL) {
        pam_syslog(pamh, LOG_ERR, "missing 'group' option");
        rc = PAM_SERVICE_ERR;
        goto ret;
    }

    if (allowed_services == NULL) {
        pam_syslog(pamh, LOG_ERR, "missing 'services' option");
        rc = PAM_SERVICE_ERR;
        goto ret;
    }

    // Only allow users in the specified group to use this module.
    uid_t uid = getuid();
    if (!pam_modutil_user_in_group_uid_nam(pamh, uid, allowed_group)) {
        if (debug) {
            pam_syslog(pamh,
                       LOG_DEBUG,
                       "uid %i not in %s group",
                       uid,
                       allowed_group);
        }
        rc = PAM_IGNORE;
        goto ret;
    }
    if (debug) {
        pam_syslog(pamh, LOG_DEBUG, "uid %i in %s group", uid, allowed_group);
    }

    // Only allow specified services. For example for an ssh login attempt it
    // would be a bad idea to allow authentication with this module.
    const char* service = NULL;
    rc = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    if (rc != PAM_SUCCESS || service == NULL) {
        pam_syslog(pamh, LOG_CRIT, "failed to get PAM_SERVICE: %i", rc);
        rc = PAM_SYSTEM_ERR;
        goto ret;
    }

    size_t service_len = strlen(service);
    size_t allowed_services_len = strlen(allowed_services);
    bool service_allowed = false;
    for (size_t i = 0; i < allowed_services_len;) {
        size_t len = strcspn(&allowed_services[i], ",");
        if (len == service_len &&
            memcmp(service, &allowed_services[i], len) == 0)
        {
            service_allowed = true;
            break;
        }
        i += len + 1;
    }

    if (!service_allowed) {
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
        pam_syslog(pamh,
                LOG_CRIT,
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

    sf = fdopen(s, "r+");
    if (sf == NULL) {
        pam_syslog(pamh,
                   LOG_ERR,
                   "failed to create stream from socket: %i",
                   errno);
        rc = PAM_SYSTEM_ERR;
        goto ret;
    }

    if (fprintf(sf, "pam-service+%s\n", service) < 0 || fflush(sf) != 0) {
        pam_syslog(pamh, LOG_ERR, "failed to write to socket: %i", errno);
        rc = PAM_SYSTEM_ERR;
        goto ret;
    }

    char res[100] = {};
    if (fgets(res, sizeof(res), sf) == NULL) {
        pam_syslog(pamh, LOG_ERR, "failed to read from socket");
        rc = PAM_SYSTEM_ERR;
        goto ret;
    }
    size_t res_len = strlen(res);
    if (res_len == 0 || res[res_len - 1] != '\n') {
        pam_syslog(pamh, LOG_ERR, "received incomplete response");
        rc = PAM_SYSTEM_ERR;
        goto ret;
    }
    res[res_len - 1] = '\0';
    res_len -= 1;

    // Since the other side is trusted this isn't strictly necessary. But it's
    // probably still nicer to ensure that we don't put unexpected bytes into
    // the log.
    for (size_t i = 0; i < res_len; i += 1) {
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
        if ((sf != NULL ? fclose(sf) : close(s)) != 0) {
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
