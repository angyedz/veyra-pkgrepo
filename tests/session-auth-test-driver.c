#define _GNU_SOURCE

#include "session-grant.h"

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;

    struct veyra_session_account account;
    if (veyra_session_resolve_account(argv[1], &account) < 0) {
        perror("test driver: account resolution");
        return 3;
    }
    char token[65] = {0};
    if (veyra_session_issue_grant(&account, argv[2], token) < 0) {
        perror("test driver: issue grant");
        return 4;
    }

    if (setgroups(0, NULL) < 0 ||
        setresgid((gid_t)account.system_gid, (gid_t)account.system_gid,
                  (gid_t)account.system_gid) < 0 ||
        setresuid((uid_t)account.system_uid, (uid_t)account.system_uid,
                  (uid_t)account.system_uid) < 0) {
        perror("test driver: drop credentials");
        return 5;
    }

    if (printf("READY\t%s\t%ld\n", token, (long)getpid()) < 0 ||
        fflush(stdout) != 0)
        return 6;
    for (;;) pause();
}
