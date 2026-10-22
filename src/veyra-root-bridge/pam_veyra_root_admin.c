#define _GNU_SOURCE
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define POLICY_DIR "/etc/veyra"
#define POLICY_FILE "root-admins"
#define TRUSTED_TTY "/dev/tty9"
#define MAX_POLICY_BYTES 65536U
#define MAX_POLICY_LINE 128U
#define MAX_POLICY_ACCOUNTS 128U

static const char *trusted_tty_path(void) {
#ifdef VEYRA_ROOT_BRIDGE_TEST_TTY
    const char *test_tty = getenv("VEYRA_ROOT_BRIDGE_TEST_TTY");
    if (test_tty != NULL && test_tty[0] == '/')
        return test_tty;
#endif
    return TRUSTED_TTY;
}

static int trusted_root_object(const struct stat *st, bool directory) {
    if ((directory && !S_ISDIR(st->st_mode)) ||
        (!directory && !S_ISREG(st->st_mode)) ||
        st->st_uid != 0 || st->st_gid != 0 ||
        (st->st_mode & 0022) != 0)
        return 0;
    if (!directory && (st->st_nlink != 1 || (st->st_mode & 0777) != 0600))
        return 0;
    return 1;
}

static int valid_account_name(const char *name, size_t length) {
    if (length == 0 || length >= MAX_POLICY_LINE)
        return 0;
    if (!((name[0] >= 'a' && name[0] <= 'z') ||
          (name[0] >= 'A' && name[0] <= 'Z') || name[0] == '_'))
        return 0;
    for (size_t i = 1; i < length; i++) {
        const char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int eligible_system_account(const char *name) {
    if (name == NULL || name[0] == '\0' || strcmp(name, "root") == 0)
        return 0;
    long buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buffer_size < 1024 || buffer_size > 1024 * 1024)
        buffer_size = 16384;
    char *buffer = malloc((size_t)buffer_size);
    if (buffer == NULL)
        return -1;
    struct passwd record;
    struct passwd *result = NULL;
    const int status = getpwnam_r(name, &record, buffer,
                                  (size_t)buffer_size, &result);
    const int eligible = status == 0 && result != NULL && result->pw_uid != 0;
    free(buffer);
    return eligible;
}

static int is_initial_id_namespace(void) {
    static const char *const maps[] = {
        "/proc/self/uid_map",
        "/proc/self/gid_map",
    };
    for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++) {
        char contents[128];
        const int fd = open(maps[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
            return 0;
        const ssize_t amount = read(fd, contents, sizeof(contents) - 1U);
        const int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        if (amount <= 0 || (size_t)amount >= sizeof(contents) - 1U)
            return 0;
        contents[amount] = '\0';
        unsigned long long inside = 0;
        unsigned long long outside = 0;
        unsigned long long length = 0;
        char extra = '\0';
        if (sscanf(contents, "%llu %llu %llu %c", &inside, &outside,
                   &length, &extra) != 3 || inside != 0 || outside != 0 ||
            length != 4294967295ULL)
            return 0;
    }
    return 1;
}

static int policy_allows(const char *username) {
    if (eligible_system_account(username) != 1)
        return 0;

    const int directory_fd = open(POLICY_DIR,
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0)
        return -1;
    struct stat directory_stat;
    if (fstat(directory_fd, &directory_stat) < 0 ||
        !trusted_root_object(&directory_stat, true)) {
        close(directory_fd);
        errno = EPERM;
        return -1;
    }

    const int policy_fd = openat(directory_fd, POLICY_FILE,
                                 O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    const int open_error = errno;
    close(directory_fd);
    if (policy_fd < 0) {
        errno = open_error;
        return -1;
    }

    struct stat policy_stat;
    if (fstat(policy_fd, &policy_stat) < 0 ||
        !trusted_root_object(&policy_stat, false) ||
        policy_stat.st_size < 0 ||
        (uintmax_t)policy_stat.st_size > MAX_POLICY_BYTES) {
        close(policy_fd);
        errno = EPERM;
        return -1;
    }

    FILE *policy = fdopen(policy_fd, "r");
    if (policy == NULL) {
        close(policy_fd);
        return -1;
    }

    char *line = NULL;
    size_t capacity = 0;
    size_t entries = 0;
    int allowed = 0;
    int invalid = 0;
    ssize_t amount;
    while ((amount = getline(&line, &capacity, policy)) >= 0) {
        size_t length = (size_t)amount;
        if (length > 0 && line[length - 1] == '\n')
            length--;
        if (length == 0 || line[0] == '#')
            continue;
        if (!valid_account_name(line, length) || ++entries > MAX_POLICY_ACCOUNTS) {
            invalid = 1;
            break;
        }
        line[length] = '\0';
        if (strcmp(line, username) == 0)
            allowed = 1;
    }
    if (ferror(policy))
        invalid = 1;
    free(line);
    if (fclose(policy) != 0)
        invalid = 1;
    if (invalid) {
        errno = EINVAL;
        return -1;
    }
    return allowed;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
    (void)flags;
    (void)argc;
    (void)argv;
    if (getuid() != 0 || geteuid() != 0 || getgid() != 0 ||
        getegid() != 0 || !is_initial_id_namespace())
        return PAM_SESSION_ERR;

    const void *service = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, &service) != PAM_SUCCESS ||
        service == NULL || strcmp(service, "veyra-root-bridge") != 0)
        return PAM_SERVICE_ERR;

    const void *tty = NULL;
    if (pam_get_item(pamh, PAM_TTY, &tty) != PAM_SUCCESS || tty == NULL ||
        strcmp(tty, trusted_tty_path()) != 0)
        return PAM_PERM_DENIED;

    const char *username = NULL;
    const int get_user_status = pam_get_user(pamh, &username, NULL);
    if (get_user_status != PAM_SUCCESS || username == NULL || username[0] == '\0')
        return PAM_USER_UNKNOWN;

    const int allowed = policy_allows(username);
    if (allowed == 1) {
        pam_syslog(pamh, LOG_INFO, "system-root bridge account authorized");
        return PAM_SUCCESS;
    }
    if (allowed < 0) {
        pam_syslog(pamh, LOG_ERR, "system-root bridge policy unavailable or invalid");
        return PAM_SERVICE_ERR;
    }
    pam_syslog(pamh, LOG_NOTICE, "system-root bridge account denied by policy");
    return PAM_PERM_DENIED;
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

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SERVICE_ERR;
}
