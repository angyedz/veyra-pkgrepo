#define _GNU_SOURCE

#include "session-grant.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef REGISTRY_PATH
#define REGISTRY_PATH "/usr/sbin/veyra-account-registry"
#endif
#define PROC_ROOT "/proc"
#define MAX_REGISTRY_OUTPUT 512U
#define MAX_ACCOUNT_NAME 32U

static int valid_account_name(const char *name) {
    if (name == NULL) return 0;
    size_t length = strlen(name);
    if (length == 0U || length > MAX_ACCOUNT_NAME ||
        !((name[0] >= 'a' && name[0] <= 'z') || name[0] == '_'))
        return 0;
    for (size_t i = 1U; i < length; ++i) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

static int parse_u32(const char *text, uint32_t *value) {
    if (text == NULL || *text == '\0' || text[0] == '+' || text[0] == '-')
        return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX)
        return -1;
    char canonical[16];
    if (snprintf(canonical, sizeof(canonical), "%llu", parsed) < 0 ||
        strcmp(canonical, text) != 0)
        return -1;
    *value = (uint32_t)parsed;
    return 0;
}

static int parse_registry_record(char *output, const char *wanted_name,
                                 struct veyra_session_account *account) {
    char *newline = strchr(output, '\n');
    if (newline == NULL || newline[1] != '\0') return -1;
    *newline = '\0';

    char *fields[5];
    size_t count = 0U;
    char *cursor = output;
    while (count < 5U) {
        fields[count++] = cursor;
        char *tab = strchr(cursor, '\t');
        if (tab == NULL) break;
        *tab = '\0';
        cursor = tab + 1;
    }
    if (count != 5U || strchr(fields[4], '\t') != NULL ||
        strcmp(fields[0], "resolved") != 0 ||
        strcmp(fields[1], wanted_name) != 0 ||
        strlen(fields[1]) > MAX_ACCOUNT_NAME)
        return -1;

    memset(account, 0, sizeof(*account));
    memcpy(account->name, fields[1], strlen(fields[1]) + 1U);
    if (parse_u32(fields[2], &account->system_uid) < 0 ||
        parse_u32(fields[3], &account->system_gid) < 0 ||
        parse_u32(fields[4], &account->uid_base) < 0 ||
        account->system_uid == 0U || account->system_gid == 0U ||
        account->uid_base < 300000U || account->uid_base % 100000U != 0U ||
        account->uid_base > UINT32_MAX - 65536U)
        return -1;
    return 0;
}

static void close_child_descriptors(void) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) == 0) return;
#endif
    _exit(126);
}

int veyra_session_resolve_account(const char *name,
                                  struct veyra_session_account *account) {
    if (!valid_account_name(name) || account == NULL) {
        errno = EINVAL;
        return -1;
    }

    struct passwd entry;
    struct passwd *found = NULL;
    char passwd_buffer[16384];
    int lookup = getpwnam_r(name, &entry, passwd_buffer,
                            sizeof(passwd_buffer), &found);
    if (lookup != 0 || found == NULL || found->pw_uid == 0U ||
        found->pw_gid == 0U) {
        errno = lookup != 0 ? lookup : ENOENT;
        return -1;
    }

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0) return -1;
    pid_t child = fork();
    if (child < 0) {
        int saved = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        errno = saved;
        return -1;
    }
    if (child == 0) {
        close(pipefd[0]);
        int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0 ||
            dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(nullfd, STDERR_FILENO) < 0)
            _exit(126);
        if (nullfd > STDERR_FILENO) close(nullfd);
        close(pipefd[1]);
        close_child_descriptors();
        char *const argv[] = { (char *)REGISTRY_PATH, (char *)"resolve",
                               (char *)name, NULL };
        char *const envp[] = { (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                               (char *)"LC_ALL=C", NULL };
        execve(REGISTRY_PATH, argv, envp);
        _exit(127);
    }

    close(pipefd[1]);
    char output[MAX_REGISTRY_OUTPUT];
    size_t used = 0U;
    int overflow = 0;
    for (;;) {
        char discard[128];
        char *target = used < sizeof(output) - 1U ? output + used : discard;
        size_t available = used < sizeof(output) - 1U
            ? sizeof(output) - 1U - used : sizeof(discard);
        ssize_t amount = read(pipefd[0], target, available);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) { overflow = 1; break; }
        if (amount == 0) break;
        if (used < sizeof(output) - 1U) {
            size_t copied = (size_t)amount;
            if (copied > available) copied = available;
            used += copied;
            if ((size_t)amount > copied) overflow = 1;
        } else {
            overflow = 1;
        }
    }
    close(pipefd[0]);
    output[used] = '\0';

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        return -1;
    }
    if (overflow || !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        parse_registry_record(output, name, account) < 0 ||
        account->system_uid != (uint32_t)found->pw_uid ||
        account->system_gid != (uint32_t)found->pw_gid) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static int ensure_runtime_dir(void) {
    int runfd = open(VEYRA_SESSION_GRANT_PARENT,
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (runfd < 0) return -1;
    struct stat runst;
    if (fstat(runfd, &runst) < 0 || !S_ISDIR(runst.st_mode) ||
        runst.st_uid != 0U || (runst.st_mode & 0022) != 0U) {
        close(runfd);
        errno = EPERM;
        return -1;
    }
    if (mkdirat(runfd, VEYRA_SESSION_GRANT_SUBDIR, 0700) < 0 &&
        errno != EEXIST) {
        int saved = errno;
        close(runfd);
        errno = saved;
        return -1;
    }
    int dirfd = openat(runfd, VEYRA_SESSION_GRANT_SUBDIR,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int saved = errno;
    close(runfd);
    if (dirfd < 0) { errno = saved; return -1; }
    struct stat st;
    int valid = fstat(dirfd, &st) == 0 && S_ISDIR(st.st_mode) &&
                st.st_uid == 0U && (st.st_mode & 07777) == 0700;
    saved = errno;
    close(dirfd);
    if (!valid) { errno = saved != 0 ? saved : EPERM; return -1; }
    return 0;
}

static int open_runtime_dir(void) {
    if (ensure_runtime_dir() < 0) return -1;
    return open(VEYRA_SESSION_GRANT_DIR,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

static int valid_token(const char *token) {
    if (token == NULL || strlen(token) != VEYRA_SESSION_TOKEN_HEX_LENGTH)
        return 0;
    for (size_t i = 0; i < VEYRA_SESSION_TOKEN_HEX_LENGTH; ++i) {
        char c = token[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static int fill_random(unsigned char *buffer, size_t length) {
    size_t offset = 0U;
    while (offset < length) {
        ssize_t amount = getrandom(buffer + offset, length - offset, 0);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int token_from_random(char token[65]) {
    unsigned char random[32];
    if (fill_random(random, sizeof(random)) < 0) return -1;
    for (size_t i = 0; i < sizeof(random); ++i) {
        int written = snprintf(token + (i * 2U), 3U, "%02x", random[i]);
        if (written != 2) { errno = EIO; return -1; }
    }
    token[64] = '\0';
    memset(random, 0, sizeof(random));
    return 0;
}

static int normalize_tty_path(const char *tty, char *path, size_t size) {
    if (tty == NULL || *tty == '\0' || strchr(tty, '\n') != NULL ||
        strchr(tty, '\r') != NULL || strstr(tty, "..") != NULL)
        return -1;
    int length;
    if (strncmp(tty, "/dev/", 5U) == 0) {
        length = snprintf(path, size, "%s", tty);
    } else if (tty[0] != '/') {
        length = snprintf(path, size, "/dev/%s", tty);
    } else {
        return -1;
    }
    return length < 0 || (size_t)length >= size ? -1 : 0;
}

static int read_process_identity(pid_t pid, uid_t *uid, gid_t *gid,
                                 pid_t *sid, uint64_t *starttime,
                                 uint64_t *tty_device) {
    if (pid <= 1 || uid == NULL || gid == NULL || sid == NULL ||
        starttime == NULL || tty_device == NULL) {
        errno = EINVAL;
        return -1;
    }
    int pidfd = -1;
    int procfd = -1;
    int processfd = -1;
    int fd = -1;
    int ttyfd = -1;
    int result = -1;
    int saved = 0;
    char pid_text[32];
    if (snprintf(pid_text, sizeof(pid_text), "%ld", (long)pid)
        >= (int)sizeof(pid_text)) { errno = ENAMETOOLONG; return -1; }
#ifdef SYS_pidfd_open
    pidfd = (int)syscall(SYS_pidfd_open, pid, 0U);
    if (pidfd < 0) return -1;
#else
    errno = ENOSYS;
    return -1;
#endif
    procfd = open(PROC_ROOT, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (procfd < 0) goto done;
    processfd = openat(procfd, pid_text,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (processfd < 0) goto done;
    fd = openat(processfd, "status", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) goto done;
    char status[8192];
    ssize_t bytes = read(fd, status, sizeof(status) - 1U);
    saved = errno;
    close(fd);
    fd = -1;
    if (bytes <= 0 || (size_t)bytes >= sizeof(status) - 1U) {
        errno = bytes < 0 ? saved : EIO;
        goto done;
    }
    status[bytes] = '\0';
    char *uid_line = strstr(status, "Uid:");
    char *gid_line = strstr(status, "Gid:");
    unsigned long real_uid, effective_uid, saved_uid, fs_uid;
    unsigned long real_gid, effective_gid, saved_gid, fs_gid;
    if (uid_line == NULL || gid_line == NULL ||
        sscanf(uid_line + 4, "%lu %lu %lu %lu", &real_uid, &effective_uid,
               &saved_uid, &fs_uid) != 4 ||
        sscanf(gid_line + 4, "%lu %lu %lu %lu", &real_gid, &effective_gid,
               &saved_gid, &fs_gid) != 4 ||
        real_uid > UINT32_MAX || real_gid > UINT32_MAX) {
        errno = EACCES;
        goto done;
    }
    (void)effective_uid; (void)saved_uid; (void)fs_uid;
    (void)effective_gid; (void)saved_gid; (void)fs_gid;

    fd = openat(processfd, "stat", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) goto done;
    char statline[8192];
    bytes = read(fd, statline, sizeof(statline) - 1U);
    saved = errno;
    close(fd);
    fd = -1;
    if (bytes <= 0 || (size_t)bytes >= sizeof(statline) - 1U) {
        errno = bytes < 0 ? saved : EIO;
        goto done;
    }
    statline[bytes] = '\0';
    char *close_paren = strrchr(statline, ')');
    if (close_paren == NULL || close_paren[1] != ' ') {
        errno = EIO;
        goto done;
    }
    char state = '\0';
    long parent_pid, process_group, process_session;
    if (sscanf(close_paren + 2, "%c %ld %ld %ld", &state, &parent_pid,
               &process_group, &process_session) != 4 || state == 'Z' ||
        process_session <= 1 || process_session > INT_MAX) {
        errno = EACCES;
        goto done;
    }
    (void)parent_pid; (void)process_group;
    /* starttime is field 22; after state and fields 4..21 there are 19 values. */
    char *cursor = close_paren + 2;
    if (*cursor == '\0' || cursor[1] != ' ') {
        errno = EIO;
        goto done;
    }
    cursor += 2;
    char *end = NULL;
    for (unsigned field = 4U; field < 22U; ++field) {
        while (*cursor == ' ') ++cursor;
        if (*cursor == '\0') { errno = EIO; goto done; }
        (void)strtoll(cursor, &end, 10);
        if (end == cursor) { errno = EIO; goto done; }
        cursor = end;
    }
    while (*cursor == ' ') ++cursor;
    errno = 0;
    unsigned long long parsed_start = strtoull(cursor, &end, 10);
    if (errno != 0 || end == cursor) { errno = EIO; goto done; }

    ttyfd = openat(processfd, "fd/0",
                   O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    if (ttyfd < 0) goto done;
    struct stat tty_stat;
    if (fstat(ttyfd, &tty_stat) < 0 || !S_ISCHR(tty_stat.st_mode)) {
        errno = ENOTTY;
        goto done;
    }
    *uid = (uid_t)real_uid;
    *gid = (gid_t)real_gid;
    *sid = (pid_t)process_session;
    *starttime = (uint64_t)parsed_start;
    *tty_device = (uint64_t)tty_stat.st_rdev;
    struct pollfd process_poll = { .fd = pidfd, .events = POLLIN };
    int poll_result = poll(&process_poll, 1U, 0);
    if (poll_result < 0) goto done;
    if (poll_result > 0) { errno = ESRCH; goto done; }
    result = 0;
done:
    if (result < 0) saved = errno;
    if (ttyfd >= 0) close(ttyfd);
    if (fd >= 0) close(fd);
    if (processfd >= 0) close(processfd);
    if (procfd >= 0) close(procfd);
    if (pidfd >= 0) close(pidfd);
    if (result < 0) errno = saved != 0 ? saved : EACCES;
    return result;
}

int veyra_session_issue_grant(const struct veyra_session_account *account,
                              const char *tty, char token[65]) {
    if (geteuid() != 0U || account == NULL || token == NULL ||
        !valid_account_name(account->name) || tty == NULL) {
        errno = EPERM;
        return -1;
    }
    struct passwd entry;
    struct passwd *found = NULL;
    char buffer[16384];
    int lookup = getpwnam_r(account->name, &entry, buffer, sizeof(buffer), &found);
    if (lookup != 0 || found == NULL ||
        (uint32_t)found->pw_uid != account->system_uid ||
        (uint32_t)found->pw_gid != account->system_gid) {
        errno = EACCES;
        return -1;
    }
    char tty_path[PATH_MAX];
    if (normalize_tty_path(tty, tty_path, sizeof(tty_path)) < 0) {
        errno = EINVAL;
        return -1;
    }
    struct stat tty_stat;
    if (stat(tty_path, &tty_stat) < 0 || !S_ISCHR(tty_stat.st_mode)) {
        errno = ENOTTY;
        return -1;
    }
    int tty_fd = open(tty_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    if (tty_fd < 0) return -1;
    pid_t tty_sid = -1;
    int ioctl_result = ioctl(tty_fd, TIOCGSID, &tty_sid);
    int saved = errno;
    close(tty_fd);
    if (ioctl_result < 0 || tty_sid <= 1 || tty_sid != getsid(0)) {
        errno = ioctl_result < 0 ? saved : EACCES;
        return -1;
    }
    uid_t real_uid;
    gid_t real_gid;
    pid_t process_sid;
    uint64_t starttime;
    uint64_t process_tty;
    if (read_process_identity(getpid(), &real_uid, &real_gid, &process_sid,
                              &starttime, &process_tty) < 0 ||
        process_sid != tty_sid || process_tty != (uint64_t)tty_stat.st_rdev) {
        errno = EACCES;
        return -1;
    }
    (void)real_uid;
    (void)real_gid;

    if (token_from_random(token) < 0) return -1;
    int dirfd = open_runtime_dir();
    if (dirfd < 0) return -1;
    struct veyra_session_grant grant;
    memset(&grant, 0, sizeof(grant));
    memcpy(grant.magic, VEYRA_SESSION_GRANT_MAGIC,
           sizeof(VEYRA_SESSION_GRANT_MAGIC));
    memcpy(grant.account, account->name, strlen(account->name) + 1U);
    grant.system_uid = account->system_uid;
    grant.system_gid = account->system_gid;
    grant.uid_base = account->uid_base;
    grant.session_id = (int32_t)process_sid;
    grant.pam_pid = (int32_t)getpid();
    grant.pam_starttime_ticks = starttime;
    grant.tty_device = (uint64_t)tty_stat.st_rdev;
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) < 0) {
        int err = errno; close(dirfd); errno = err; return -1;
    }
    grant.issued_boottime_seconds = (uint64_t)now.tv_sec;

    int fd = openat(dirfd, token, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                    O_NOFOLLOW, 0600);
    if (fd < 0) { int err = errno; close(dirfd); errno = err; return -1; }
    struct stat created;
    int result = fstat(fd, &created);
    if (result == 0 && (!S_ISREG(created.st_mode) || created.st_uid != 0U ||
                        (created.st_mode & 07777) != 0600 ||
                        created.st_nlink != 1)) {
        result = -1;
        errno = EPERM;
    }
    if (result == 0) {
        const unsigned char *data = (const unsigned char *)&grant;
        size_t remaining = sizeof(grant);
        while (remaining > 0U) {
            ssize_t written = write(fd, data, remaining);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) { result = -1; break; }
            data += (size_t)written;
            remaining -= (size_t)written;
        }
    }
    if (result == 0 && fsync(fd) < 0) result = -1;
    int err = errno;
    if (close(fd) < 0 && result == 0) { result = -1; err = errno; }
    if (result == 0 && fsync(dirfd) < 0) { result = -1; err = errno; }
    if (result < 0) (void)unlinkat(dirfd, token, 0);
    close(dirfd);
    if (result < 0) { errno = err; memset(token, 0, 65U); return -1; }
    return 0;
}

int veyra_session_remove_grant(const char *token) {
    if (geteuid() != 0U || !valid_token(token)) { errno = EPERM; return -1; }
    int dirfd = open_runtime_dir();
    if (dirfd < 0) return -1;
    struct stat st;
    if (fstatat(dirfd, token, &st, AT_SYMLINK_NOFOLLOW) < 0) {
        int saved = errno;
        close(dirfd);
        if (saved == ENOENT) return 0;
        errno = saved;
        return -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != 0U ||
        (st.st_mode & 07777) != 0600 || st.st_nlink != 1) {
        close(dirfd);
        errno = EPERM;
        return -1;
    }
    int result = unlinkat(dirfd, token, 0);
    int saved = errno;
    close(dirfd);
    if (result < 0 && saved == ENOENT) return 0;
    if (result < 0) errno = saved;
    return result;
}

int veyra_session_consume_grant(const char *token, pid_t peer_pid,
                                struct veyra_session_grant *grant_out) {
    if (geteuid() != 0U || !valid_token(token) || peer_pid <= 1 ||
        grant_out == NULL) { errno = EPERM; return -1; }
    int dirfd = open_runtime_dir();
    if (dirfd < 0) return -1;
    int fd = openat(dirfd, token, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) { int err = errno; close(dirfd); errno = err; return -1; }
    if (flock(fd, LOCK_EX) < 0) {
        int err = errno; close(fd); close(dirfd); errno = err; return -1;
    }
    struct stat opened;
    struct stat named;
    int result = fstat(fd, &opened);
    if (result == 0 && (!S_ISREG(opened.st_mode) || opened.st_uid != 0U ||
                        (opened.st_mode & 07777) != 0600 || opened.st_nlink != 1 ||
                        opened.st_size != (off_t)sizeof(*grant_out))) {
        result = -1;
        errno = EPERM;
    }
    struct veyra_session_grant grant;
    if (result == 0) {
        unsigned char *data = (unsigned char *)&grant;
        size_t remaining = sizeof(grant);
        while (remaining > 0U) {
            ssize_t amount = read(fd, data, remaining);
            if (amount < 0 && errno == EINTR) continue;
            if (amount <= 0) { result = -1; errno = EIO; break; }
            data += (size_t)amount;
            remaining -= (size_t)amount;
        }
    }
    if (result == 0 &&
        (memcmp(grant.magic, VEYRA_SESSION_GRANT_MAGIC,
                sizeof(VEYRA_SESSION_GRANT_MAGIC)) != 0 ||
         !valid_account_name(grant.account) || grant.system_uid == 0U ||
         grant.system_gid == 0U || grant.uid_base < 300000U ||
         grant.uid_base % 100000U != 0U ||
         grant.uid_base > UINT32_MAX - 65536U || grant.pam_pid != peer_pid)) {
#ifdef VEYRA_SESSION_AUTH_DEBUG
        fprintf(stderr, "grant debug: stored identity rejected (pid=%d peer=%ld)\n",
                grant.pam_pid, (long)peer_pid);
#endif
        result = -1;
        errno = EACCES;
    }
    struct timespec now;
    if (result == 0) {
        if (clock_gettime(CLOCK_BOOTTIME, &now) < 0) {
            result = -1;
        } else if (now.tv_sec < 0 ||
                   (uint64_t)now.tv_sec < grant.issued_boottime_seconds ||
                   (uint64_t)now.tv_sec - grant.issued_boottime_seconds >
                       VEYRA_SESSION_GRANT_TTL_SECONDS) {
            result = -1;
            errno = ETIMEDOUT;
        }
    }
    uid_t peer_uid = (uid_t)-1;
    gid_t peer_gid = (gid_t)-1;
    pid_t peer_sid = (pid_t)-1;
    uint64_t peer_starttime = 0U;
    uint64_t peer_tty_device = 0U;
    if (result == 0) {
        int identity_result = read_process_identity(
            peer_pid, &peer_uid, &peer_gid, &peer_sid, &peer_starttime,
            &peer_tty_device);
        if (identity_result < 0 || peer_uid != grant.system_uid ||
            peer_gid != grant.system_gid || peer_sid != grant.session_id ||
            peer_starttime != grant.pam_starttime_ticks ||
            peer_tty_device != grant.tty_device) {
#ifdef VEYRA_SESSION_AUTH_DEBUG
            fprintf(stderr,
                    "grant debug: process identity rejected (read=%d errno=%d uid=%lu/%u gid=%lu/%u sid=%ld/%d start=%llu/%llu tty=%llu/%llu)\n",
                    identity_result, errno, (unsigned long)peer_uid,
                    grant.system_uid, (unsigned long)peer_gid,
                    grant.system_gid, (long)peer_sid, grant.session_id,
                    (unsigned long long)peer_starttime,
                    (unsigned long long)grant.pam_starttime_ticks,
                    (unsigned long long)peer_tty_device,
                    (unsigned long long)grant.tty_device);
#endif
            result = -1;
            errno = EACCES;
        }
    }
    struct veyra_session_account current;
    if (result == 0 &&
        (veyra_session_resolve_account(grant.account, &current) < 0 ||
         current.system_uid != grant.system_uid ||
         current.system_gid != grant.system_gid ||
         current.uid_base != grant.uid_base)) {
#ifdef VEYRA_SESSION_AUTH_DEBUG
        fprintf(stderr, "grant debug: current account mapping rejected (errno=%d)\n",
                errno);
#endif
        result = -1;
        errno = EACCES;
    }
    if (result == 0 && fstatat(dirfd, token, &named, AT_SYMLINK_NOFOLLOW) < 0) {
        result = -1;
    }
    if (result == 0 && (named.st_dev != opened.st_dev || named.st_ino != opened.st_ino)) {
        result = -1;
        errno = EAGAIN;
    }
    if (result == 0 && unlinkat(dirfd, token, 0) < 0) result = -1;
    int saved = errno;
    close(fd);
    if (result == 0 && fsync(dirfd) < 0) { result = -1; saved = errno; }
    close(dirfd);
    if (result < 0) { errno = saved != 0 ? saved : EACCES; return -1; }
    *grant_out = grant;
    return 0;
}
