#define _GNU_SOURCE

#include "session-grant.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int parse_pid(const char *text, pid_t *pid) {
    if (text == NULL || *text == '\0' || text[0] == '+' || text[0] == '-')
        return -1;
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 1 ||
        value > INT_MAX)
        return -1;
    *pid = (pid_t)value;
    return 0;
}

int main(int argc, char **argv) {
    if (geteuid() != 0U) {
        fputs("veyra-session-grant: root privileges are required\n", stderr);
        return 1;
    }
    if (argc != 4 || strcmp(argv[1], "consume") != 0) {
        fputs("Usage: veyra-session-grant consume TOKEN PEER_PID\n", stderr);
        return 2;
    }
    pid_t peer_pid;
    if (parse_pid(argv[3], &peer_pid) < 0) {
        fputs("veyra-session-grant: invalid peer PID\n", stderr);
        return 2;
    }
    struct veyra_session_grant grant;
    if (veyra_session_consume_grant(argv[2], peer_pid, &grant) < 0) {
#ifdef VEYRA_SESSION_AUTH_DEBUG
        fprintf(stderr, "veyra-session-grant: debug: %s\n", strerror(errno));
#endif
        fputs("veyra-session-grant: session grant was rejected\n", stderr);
        return 1;
    }
    printf("authorized\t%s\t%u\t%u\t%u\t%d\t%ld\t%ld\n",
           grant.account, grant.system_uid, grant.system_gid, grant.uid_base,
           grant.session_id, (long)(grant.tty_device >> 32),
           (long)(grant.tty_device & 0xffffffffU));
    return ferror(stdout) ? 1 : 0;
}
