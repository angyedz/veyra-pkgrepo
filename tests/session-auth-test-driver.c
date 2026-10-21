#define _GNU_SOURCE

#include <security/pam_appl.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

static int no_conversation(int message_count,
                           const struct pam_message **messages,
                           struct pam_response **responses, void *data) {
    (void)message_count;
    (void)messages;
    (void)responses;
    (void)data;
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
    if (argc != 2) return 2;

    struct pam_conv conversation = { .conv = no_conversation, .appdata_ptr = NULL };
    pam_handle_t *pamh = NULL;
    int status = pam_start("veyra-login", "nobody", &conversation, &pamh);
    if (status != PAM_SUCCESS || pamh == NULL) {
        fputs("test login: pam_start failed\n", stderr);
        return 3;
    }

    if (pam_step(pamh, pam_set_item(pamh, PAM_TTY, argv[1]), "set TTY") ||
        pam_step(pamh, pam_authenticate(pamh, 0), "authenticate") ||
        pam_step(pamh, pam_acct_mgmt(pamh, 0), "account check") ||
        pam_step(pamh, pam_open_session(pamh, 0), "open session")) {
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 4;
    }

    const char *token = pam_getenv(pamh, "VEYRA_SESSION_TOKEN");
    if (token == NULL || strlen(token) != 64U) {
        fputs("test login: PAM session did not export a grant token\n", stderr);
        (void)pam_close_session(pamh, 0);
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 5;
    }
    char token_copy[65];
    memcpy(token_copy, token, sizeof(token_copy));

    if (setresgid(65534, 0, 0) < 0 || setresuid(65534, 0, 0) < 0) {
        perror("test login: retain root broker while setting real account IDs");
        (void)pam_close_session(pamh, 0);
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 6;
    }

    struct sigaction stop_action = {0};
    stop_action.sa_handler = request_stop;
    sigemptyset(&stop_action.sa_mask);
    if (sigaction(SIGTERM, &stop_action, NULL) < 0) {
        perror("test login: sigaction");
        (void)pam_close_session(pamh, 0);
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 7;
    }

    if (printf("READY\t%s\t%ld\n", token_copy, (long)getpid()) < 0 ||
        fflush(stdout) != 0) {
        (void)pam_close_session(pamh, 0);
        (void)pam_end(pamh, PAM_SESSION_ERR);
        return 8;
    }
    while (!stop_requested) pause();

    status = pam_close_session(pamh, 0);
    int end_status = pam_end(pamh, status);
    if (status != PAM_SUCCESS || end_status != PAM_SUCCESS) {
        fputs("test login: PAM session cleanup failed\n", stderr);
        return 9;
    }
    return 0;
}
