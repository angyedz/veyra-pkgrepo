#define _GNU_SOURCE

#include <security/pam_appl.h>

#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

struct test_credentials {
    const char *username;
    const char *password;
};

static int test_conversation(int message_count,
                             const struct pam_message **messages,
                             struct pam_response **responses, void *data) {
    if (message_count <= 0 || messages == NULL || responses == NULL ||
        data == NULL) return PAM_CONV_ERR;
    const struct test_credentials *credentials = data;
    struct pam_response *result = calloc((size_t)message_count, sizeof(*result));
    if (result == NULL) return PAM_BUF_ERR;
    for (int i = 0; i < message_count; ++i) {
        if (messages[i] == NULL) goto error;
        switch (messages[i]->msg_style) {
        case PAM_PROMPT_ECHO_ON:
            result[i].resp = strdup(credentials->username);
            break;
        case PAM_PROMPT_ECHO_OFF:
            result[i].resp = strdup(credentials->password);
            break;
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            break;
        default:
            goto error;
        }
        if ((messages[i]->msg_style == PAM_PROMPT_ECHO_ON ||
             messages[i]->msg_style == PAM_PROMPT_ECHO_OFF) &&
            result[i].resp == NULL)
            goto error;
    }
    *responses = result;
    return PAM_SUCCESS;

error:
    for (int i = 0; i < message_count; ++i) free(result[i].resp);
    free(result);
    return PAM_CONV_ERR;
}

static void request_stop(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static int pam_step(pam_handle_t *pamh, int status, const char *step) {
    if (status == PAM_SUCCESS) return 0;
    fprintf(stderr, "test login: %s: %s\n", step, pam_strerror(pamh, status));
    return 1;
}

int main(int argc, char **argv) {
    int auth_only = argc == 3 && strcmp(argv[1], "auth") == 0;
    int login = argc == 4 && strcmp(argv[1], "login") == 0;
    if (!auth_only && !login) return 2;
    const char *username = argv[2];
    const char *tty = login ? argv[3] : NULL;
    const char *password = getenv("VEYRA_SESSION_TEST_PASSWORD");
    if (username == NULL || password == NULL || *password == '\0') return 2;

    struct test_credentials credentials = {
        .username = username,
        .password = password,
    };
    struct pam_conv conversation = {
        .conv = test_conversation,
        .appdata_ptr = &credentials,
    };
    pam_handle_t *pamh = NULL;
    int status = pam_start("veyra-login", username, &conversation, &pamh);
    if (status != PAM_SUCCESS || pamh == NULL) {
        fputs("test login: pam_start failed\n", stderr);
        return 3;
    }

    if (login && pam_step(pamh, pam_set_item(pamh, PAM_TTY, tty), "set TTY")) {
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 4;
    }

    status = pam_authenticate(pamh, 0);
    if (auth_only) {
        puts(status == PAM_SUCCESS ? "AUTH_ACCEPTED" : "AUTH_REJECTED");
        (void)pam_end(pamh, status);
        return 0;
    }
    if (pam_step(pamh, status, "authenticate") ||
        pam_step(pamh, pam_acct_mgmt(pamh, 0), "account check") ||
        pam_step(pamh, pam_setcred(pamh, PAM_ESTABLISH_CRED), "set credentials") ||
        pam_step(pamh, pam_open_session(pamh, 0), "open session")) {
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 5;
    }

    const char *token = pam_getenv(pamh, "VEYRA_SESSION_TOKEN");
    if (token == NULL || strlen(token) != 64U) {
        fputs("test login: PAM session did not export a grant token\n", stderr);
        (void)pam_close_session(pamh, 0);
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 6;
    }
    char token_copy[65];
    memcpy(token_copy, token, sizeof(token_copy));

    struct passwd *entry = getpwnam(username);
    if (entry == NULL) {
        fputs("test login: account disappeared after PAM authentication\n", stderr);
        (void)pam_close_session(pamh, 0);
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 7;
    }
    uid_t system_uid = entry->pw_uid;
    gid_t system_gid = entry->pw_gid;
    if (setresgid(system_gid, 0, 0) < 0 || setresuid(system_uid, 0, 0) < 0) {
        perror("test login: retain root broker while setting real account IDs");
        (void)pam_close_session(pamh, 0);
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 8;
    }

    struct sigaction stop_action = {0};
    stop_action.sa_handler = request_stop;
    sigemptyset(&stop_action.sa_mask);
    if (sigaction(SIGTERM, &stop_action, NULL) < 0) {
        perror("test login: sigaction");
        (void)pam_close_session(pamh, 0);
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 9;
    }

    if (printf("READY\t%s\t%ld\n", token_copy, (long)getpid()) < 0 ||
        fflush(stdout) != 0) {
        (void)pam_close_session(pamh, 0);
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 10;
    }
    while (!stop_requested) pause();

    status = pam_close_session(pamh, 0);
    int credential_status = pam_setcred(pamh, PAM_DELETE_CRED);
    int end_status = pam_end(pamh, status);
    if (status != PAM_SUCCESS || credential_status != PAM_SUCCESS ||
        end_status != PAM_SUCCESS) {
        fputs("test login: PAM session cleanup failed\n", stderr);
        return 11;
    }
    return 0;
}
