#define _GNU_SOURCE

#include "session-grant.h"

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_DATA_KEY "veyra-session-auth-grant-v1"
#define PAM_SERVICE_NAME "veyra-login"

struct grant_cookie {
    char token[65];
};

static void cleanup_grant(pam_handle_t *pamh, void *data, int status) {
    (void)pamh;
    (void)status;
    struct grant_cookie *cookie = data;
    if (cookie == NULL) return;
    (void)veyra_session_remove_grant(cookie->token);
    memset(cookie, 0, sizeof(*cookie));
    free(cookie);
}

static int get_pam_identity(pam_handle_t *pamh, const char **user,
                            const char **service) {
    const void *item = NULL;
    int result = pam_get_user(pamh, user, NULL);
    if (result != PAM_SUCCESS || *user == NULL || **user == '\0')
        return PAM_USER_UNKNOWN;
    result = pam_get_item(pamh, PAM_SERVICE, &item);
    if (result != PAM_SUCCESS || item == NULL) return PAM_SERVICE_ERR;
    *service = item;
    return PAM_SUCCESS;
}

static int verify_enrolled_user(pam_handle_t *pamh,
                                struct veyra_session_account *account) {
    const char *user = NULL;
    const char *service = NULL;
    int result = get_pam_identity(pamh, &user, &service);
    if (result != PAM_SUCCESS) return result;
    if (strcmp(service, PAM_SERVICE_NAME) != 0) return PAM_SERVICE_ERR;
    if (veyra_session_resolve_account(user, account) < 0) {
        pam_syslog(pamh, LOG_NOTICE,
                   "Veyra login rejected: account is not currently eligible");
        return PAM_PERM_DENIED;
    }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
    (void)flags;
    (void)argc;
    (void)argv;
    struct veyra_session_account account;
    return verify_enrolled_user(pamh, &account);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
    (void)flags;
    (void)argc;
    (void)argv;
    if (geteuid() != 0U) return PAM_SESSION_ERR;

    const void *existing = NULL;
    if (pam_get_data(pamh, PAM_DATA_KEY, &existing) == PAM_SUCCESS &&
        existing != NULL)
        return PAM_SESSION_ERR;

    struct veyra_session_account account;
    int result = verify_enrolled_user(pamh, &account);
    if (result != PAM_SUCCESS) return result;

    const void *tty_item = NULL;
    result = pam_get_item(pamh, PAM_TTY, &tty_item);
    if (result != PAM_SUCCESS || tty_item == NULL) return PAM_SESSION_ERR;

    struct grant_cookie *cookie = calloc(1U, sizeof(*cookie));
    if (cookie == NULL) return PAM_BUF_ERR;
    if (veyra_session_issue_grant(&account, tty_item, cookie->token) < 0) {
        pam_syslog(pamh, LOG_ERR,
                   "Veyra login could not issue a trusted session grant");
        free(cookie);
        return PAM_SESSION_ERR;
    }

    result = pam_set_data(pamh, PAM_DATA_KEY, cookie, cleanup_grant);
    if (result != PAM_SUCCESS) {
        cleanup_grant(pamh, cookie, result);
        return PAM_SESSION_ERR;
    }

    char environment[96];
    int length = snprintf(environment, sizeof(environment),
                          "VEYRA_SESSION_TOKEN=%s", cookie->token);
    if (length < 0 || (size_t)length >= sizeof(environment) ||
        pam_putenv(pamh, environment) != PAM_SUCCESS) {
        (void)veyra_session_remove_grant(cookie->token);
        return PAM_SESSION_ERR;
    }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) {
    (void)flags;
    (void)argc;
    (void)argv;
    const void *data = NULL;
    int result = pam_get_data(pamh, PAM_DATA_KEY, &data);
    if (result == PAM_NO_MODULE_DATA || data == NULL) return PAM_SUCCESS;
    if (result != PAM_SUCCESS || geteuid() != 0U) return PAM_SESSION_ERR;
    const struct grant_cookie *cookie = data;
    if (veyra_session_remove_grant(cookie->token) < 0) {
        pam_syslog(pamh, LOG_ERR, "Veyra session grant cleanup failed");
        return PAM_SESSION_ERR;
    }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
