#ifndef VEYRA_SESSION_GRANT_H
#define VEYRA_SESSION_GRANT_H

#include <stdint.h>
#include <sys/types.h>

#define VEYRA_SESSION_TOKEN_HEX_LENGTH 64U
#ifndef VEYRA_SESSION_GRANT_TTL_SECONDS
#define VEYRA_SESSION_GRANT_TTL_SECONDS 120U
#endif
#define VEYRA_SESSION_GRANT_MAGIC "VEYRA-GRANT-1"
#ifndef VEYRA_SESSION_GRANT_PARENT
#define VEYRA_SESSION_GRANT_PARENT "/run"
#endif
#ifndef VEYRA_SESSION_GRANT_SUBDIR
#define VEYRA_SESSION_GRANT_SUBDIR "veyra-session-auth"
#endif
#ifndef VEYRA_SESSION_GRANT_DIR
#define VEYRA_SESSION_GRANT_DIR \
    VEYRA_SESSION_GRANT_PARENT "/" VEYRA_SESSION_GRANT_SUBDIR
#endif

struct veyra_session_account {
    char name[33];
    uint32_t system_uid;
    uint32_t system_gid;
    uint32_t uid_base;
};

struct veyra_session_grant {
    char magic[16];
    char account[33];
    uint32_t system_uid;
    uint32_t system_gid;
    uint32_t uid_base;
    int32_t session_id;
    int32_t pam_pid;
    uint64_t pam_starttime_ticks;
    uint64_t tty_device;
    uint64_t issued_boottime_seconds;
};

int veyra_session_resolve_account(const char *name,
                                  struct veyra_session_account *account);
int veyra_session_issue_grant(const struct veyra_session_account *account,
                              const char *tty, char token[65]);
int veyra_session_remove_grant(const char *token);
int veyra_session_consume_grant(const char *token, pid_t peer_pid,
                                struct veyra_session_grant *grant);

#endif
