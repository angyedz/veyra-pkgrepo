#define _GNU_SOURCE
#include <security/pam_appl.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_conversation(int count, const struct pam_message **messages,
                             struct pam_response **responses, void *data) {
    if (count <= 0 || messages == NULL || responses == NULL || data == NULL)
        return PAM_CONV_ERR;
    const char *password = data;
    struct pam_response *result = calloc((size_t)count, sizeof(*result));
    if (result == NULL)
        return PAM_BUF_ERR;
    for (int i = 0; i < count; i++) {
        if (messages[i] == NULL)
            goto failed;
        switch (messages[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            result[i].resp = strdup(password);
            break;
        case PAM_PROMPT_ECHO_ON:
            result[i].resp = strdup("");
            break;
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            break;
        default:
            goto failed;
        }
        if ((messages[i]->msg_style == PAM_PROMPT_ECHO_ON ||
             messages[i]->msg_style == PAM_PROMPT_ECHO_OFF) &&
            result[i].resp == NULL)
            goto failed;
    }
    *responses = result;
    return PAM_SUCCESS;

failed:
    for (int i = 0; i < count; i++)
        free(result[i].resp);
    free(result);
    return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    const bool account_only = argc == 4 && strcmp(argv[1], "account") == 0;
    if ((!account_only && argc != 3) || (account_only && argc != 4))
        return 2;
    const char *username = argv[account_only ? 2 : 1];
    const char *tty = argv[account_only ? 3 : 2];
    const char *password = getenv("VEYRA_ROOT_BRIDGE_TEST_PASSWORD");
    if (username == NULL || tty == NULL ||
        (!account_only && (password == NULL || *password == '\0')))
        return 2;
    if (password == NULL)
        password = "";

    struct pam_conv conversation = {
        .conv = test_conversation,
        .appdata_ptr = (void *)password,
    };
    pam_handle_t *pamh = NULL;
    int status = pam_start("veyra-root-bridge", username, &conversation, &pamh);
    if (status == PAM_SUCCESS)
        status = pam_set_item(pamh, PAM_TTY, tty);
    if (status == PAM_SUCCESS && !account_only)
        status = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
    if (status != PAM_SUCCESS) {
        puts("AUTH_REJECTED");
        if (pamh != NULL)
            (void)pam_end(pamh, status);
        return 0;
    }

    status = pam_acct_mgmt(pamh, 0);
    if (status == PAM_SUCCESS && !account_only) {
        puts("AUTHENTICATED_AND_AUTHORIZED");
        (void)pam_end(pamh, PAM_SUCCESS);
    } else if (status == PAM_SUCCESS) {
        puts("ACCOUNT_AUTHORIZED");
        (void)pam_end(pamh, PAM_SUCCESS);
    } else if (account_only) {
        puts("ACCOUNT_DENIED");
        (void)pam_end(pamh, status);
    } else {
        puts("AUTHENTICATED_BUT_DENIED");
        (void)pam_end(pamh, status);
    }
    return 0;
}
