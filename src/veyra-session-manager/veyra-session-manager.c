#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <poll.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC 0xEF53U
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS 0x02U
#endif
#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT 0x10U
#endif
struct veyra_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

#define RUN_DIR "/run/veyra-session-manager"
#define SOCKET_PATH RUN_DIR "/control.sock"
#define USERS_PATH "/var/lib/veyra-user-store/users"
#define GRANT_TOOL "/usr/sbin/veyra-session-grant"
#define PROVISIONER "/usr/sbin/veyra-user-root-provisioner"
#define MAX_ACCOUNT 32U
#define TOKEN_LENGTH 64U
#define LINE_LIMIT 192U
#define MAP_LENGTH 65536U
#define MAX_TREE_ENTRIES 100000U
#define MAX_TREE_DEPTH 64U
#define RELAY_BUFFER 65536U
#define MAX_SESSION_WORKERS 32U
#define REQUEST_TIMEOUT_MS 10000

struct authorized_session {
    char account[MAX_ACCOUNT + 1U];
    uint32_t system_uid;
    uint32_t system_gid;
    uint32_t uid_base;
    int32_t session_id;
    uint32_t tty_major;
    uint32_t tty_minor;
};

struct tree_scan {
    dev_t device;
    uint32_t uid_base;
    uint32_t entries;
    char *error;
    size_t error_size;
};

static volatile sig_atomic_t stopping;
static unsigned active_workers;

static int client_login(void);

static void set_error(char *buffer, size_t size, const char *message) {
    if (size != 0U) (void)snprintf(buffer, size, "%s", message);
}

static int write_all(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    while (length > 0U) {
        ssize_t amount = write(fd, cursor, length);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        cursor += (size_t)amount;
        length -= (size_t)amount;
    }
    return 0;
}

static int valid_account(const char *name) {
    if (name == NULL) return 0;
    size_t length = strlen(name);
    if (length == 0U || length > MAX_ACCOUNT ||
        !((name[0] >= 'a' && name[0] <= 'z') || name[0] == '_'))
        return 0;
    for (size_t index = 1U; index < length; ++index) {
        char value = name[index];
        if (!((value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '_' || value == '-'))
            return 0;
    }
    return 1;
}

static int valid_token(const char *token) {
    if (token == NULL || strlen(token) != TOKEN_LENGTH) return 0;
    for (size_t index = 0U; index < TOKEN_LENGTH; ++index) {
        char value = token[index];
        if (!((value >= '0' && value <= '9') ||
              (value >= 'a' && value <= 'f')))
            return 0;
    }
    return 1;
}

static int valid_term(const char *term) {
    if (term == NULL || *term == '\0' || strlen(term) > 64U) return 0;
    for (const char *cursor = term; *cursor != '\0'; ++cursor) {
        char value = *cursor;
        if (!((value >= 'a' && value <= 'z') ||
              (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') || value == '_' ||
              value == '-' || value == '+' || value == '.' || value == ':'))
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

static int split_fields(char *line, char **fields, size_t field_count) {
    char *newline = strchr(line, '\n');
    if (newline == NULL || newline[1] != '\0') return -1;
    *newline = '\0';
    size_t count = 0U;
    char *cursor = line;
    for (;;) {
        if (count >= field_count) return -1;
        fields[count++] = cursor;
        char *tab = strchr(cursor, '\t');
        if (tab == NULL) break;
        *tab = '\0';
        cursor = tab + 1;
    }
    return count == field_count ? 0 : -1;
}

static int parse_authorized(char *line, struct authorized_session *session) {
    char *fields[8];
    uint32_t session_id = 0U;
    if (split_fields(line, fields, 8U) < 0 ||
        strcmp(fields[0], "authorized") != 0 ||
        !valid_account(fields[1]) ||
        parse_u32(fields[2], &session->system_uid) < 0 ||
        parse_u32(fields[3], &session->system_gid) < 0 ||
        parse_u32(fields[4], &session->uid_base) < 0 ||
        parse_u32(fields[5], &session_id) < 0 || session_id <= 1U ||
        session_id > INT32_MAX ||
        parse_u32(fields[6], &session->tty_major) < 0 ||
        parse_u32(fields[7], &session->tty_minor) < 0)
        return -1;
    if (session->system_uid == 0U || session->system_gid == 0U ||
        session->uid_base < 300000U || session->uid_base % 100000U != 0U ||
        session->uid_base > UINT32_MAX - MAP_LENGTH)
        return -1;
    memcpy(session->account, fields[1], strlen(fields[1]) + 1U);
    session->session_id = (int32_t)session_id;
    return 0;
}

static int parse_request(char *line, char token[TOKEN_LENGTH + 1U],
                         char term[65]) {
    char *newline = strchr(line, '\n');
    if (newline == NULL || newline[1] != '\0') return -1;
    *newline = '\0';
    if (strncmp(line, "start ", 6U) != 0) return -1;
    char *token_text = line + 6U;
    char *separator = strchr(token_text, ' ');
    if (separator == NULL || strchr(separator + 1U, ' ') != NULL) return -1;
    *separator = '\0';
    if (!valid_token(token_text) || !valid_term(separator + 1U)) return -1;
    memcpy(token, token_text, TOKEN_LENGTH + 1U);
    memcpy(term, separator + 1U, strlen(separator + 1U) + 1U);
    return 0;
}

static int safe_openat(int rootfd, const char *path, int flags) {
    struct veyra_open_how how = {
        .flags = (uint64_t)(flags | O_CLOEXEC),
        .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };
    return (int)syscall(SYS_openat2, rootfd, path, &how, sizeof(how));
}

static int allowed_device(const char *path, const struct stat *st) {
    if (!S_ISCHR(st->st_mode)) return 0;
    if (strcmp(path, "dev/console") == 0)
        return major(st->st_rdev) == 5U && minor(st->st_rdev) == 1U;
    if (strcmp(path, "dev/tty") == 0)
        return major(st->st_rdev) == 5U && minor(st->st_rdev) == 0U;
    if (strcmp(path, "dev/null") == 0)
        return major(st->st_rdev) == 1U && minor(st->st_rdev) == 3U;
    if (strcmp(path, "dev/zero") == 0)
        return major(st->st_rdev) == 1U && minor(st->st_rdev) == 5U;
    if (strcmp(path, "dev/random") == 0)
        return major(st->st_rdev) == 1U && minor(st->st_rdev) == 8U;
    if (strcmp(path, "dev/urandom") == 0)
        return major(st->st_rdev) == 1U && minor(st->st_rdev) == 9U;
    return 0;
}

static int scan_rootfs(int root_directory_fd, const char *parent, unsigned depth,
                       struct tree_scan *scan) {
    if (depth > MAX_TREE_DEPTH) {
        set_error(scan->error, scan->error_size, "rootfs directory nesting is too deep");
        return -1;
    }
    DIR *directory = fdopendir(dup(root_directory_fd));
    if (directory == NULL) {
        set_error(scan->error, scan->error_size, "cannot enumerate user rootfs");
        return -1;
    }
    struct dirent *entry;
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                set_error(scan->error, scan->error_size, "cannot read user rootfs");
                closedir(directory);
                return -1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (++scan->entries > MAX_TREE_ENTRIES) {
            set_error(scan->error, scan->error_size, "user rootfs has too many files");
            closedir(directory);
            return -1;
        }
        char path[PATH_MAX];
        int length = parent[0] == '\0'
            ? snprintf(path, sizeof(path), "%s", entry->d_name)
            : snprintf(path, sizeof(path), "%s/%s", parent, entry->d_name);
        if (length < 0 || length >= (int)sizeof(path)) {
            set_error(scan->error, scan->error_size, "user rootfs path is too long");
            closedir(directory);
            return -1;
        }
        struct stat st;
        if (fstatat(dirfd(directory), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            set_error(scan->error, scan->error_size, "user rootfs changed during validation");
            closedir(directory);
            return -1;
        }
        uint64_t limit = (uint64_t)scan->uid_base + MAP_LENGTH;
        if ((uint64_t)st.st_uid < scan->uid_base ||
            (uint64_t)st.st_uid >= limit ||
            (uint64_t)st.st_gid < scan->uid_base ||
            (uint64_t)st.st_gid >= limit || st.st_dev != scan->device) {
            set_error(scan->error, scan->error_size,
                      "user rootfs contains an unmapped owner or nested filesystem");
            closedir(directory);
            return -1;
        }
        if (S_ISDIR(st.st_mode)) {
            int child = openat(dirfd(directory), entry->d_name,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0 || scan_rootfs(child, path, depth + 1U, scan) < 0) {
                if (child >= 0) close(child);
                closedir(directory);
                return -1;
            }
            close(child);
            continue;
        }
        if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
            if ((st.st_mode & (S_ISUID | S_ISGID)) != 0) {
                if (strcmp(path, "usr/bin/sudo") != 0 || !S_ISREG(st.st_mode) ||
                    st.st_uid != scan->uid_base ||
                    (st.st_mode & 07777) != 04755) {
                    set_error(scan->error, scan->error_size,
                              "user rootfs contains an unexpected set-id file");
                    closedir(directory);
                    return -1;
                }
            }
            continue;
        }
        if (allowed_device(path, &st)) continue;
        set_error(scan->error, scan->error_size,
                  "user rootfs contains an unsupported special file");
        closedir(directory);
        return -1;
    }
    closedir(directory);
    return 0;
}

static int reject_rootfs_submounts(const char *account, char *error,
                                   size_t error_size) {
    char root_path[PATH_MAX];
    if (snprintf(root_path, sizeof(root_path), "%s/%s/rootfs",
                 USERS_PATH, account) >= (int)sizeof(root_path)) {
        set_error(error, error_size, "user rootfs path is too long");
        return -1;
    }
    FILE *mounts = fopen("/proc/self/mountinfo", "r");
    if (mounts == NULL) {
        set_error(error, error_size, "cannot inspect system mount table");
        return -1;
    }
    char *line = NULL;
    size_t capacity = 0U;
    int found = 0;
    while (getline(&line, &capacity, mounts) >= 0) {
        char *save = NULL;
        char *field = NULL;
        for (unsigned index = 0U; index < 5U; ++index) {
            field = strtok_r(index == 0U ? line : NULL, " ", &save);
            if (field == NULL) break;
        }
        if (field == NULL) continue;
        size_t root_length = strlen(root_path);
        if (strcmp(field, root_path) == 0 ||
            (strncmp(field, root_path, root_length) == 0 &&
             field[root_length] == '/')) {
            found = 1;
            break;
        }
    }
    free(line);
    fclose(mounts);
    if (found) {
        set_error(error, error_size, "user rootfs contains a nested mount");
        return -1;
    }
    return 0;
}

static int valid_shell_path(const char *shell) {
    if (shell == NULL || shell[0] != '/' || strlen(shell) < 2U ||
        strlen(shell) >= PATH_MAX || strstr(shell, "//") != NULL ||
        strstr(shell, "/../") != NULL ||
        (strlen(shell) >= 3U && strcmp(shell + strlen(shell) - 3U, "/..") == 0))
        return 0;
    for (const char *cursor = shell; *cursor != '\0'; ++cursor) {
        char value = *cursor;
        if (!((value >= 'a' && value <= 'z') ||
              (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') || value == '/' ||
              value == '_' || value == '-' || value == '+' || value == '.'))
            return 0;
    }
    return 1;
}

static int read_user_shell(int rootfd, const char *account,
                           char shell[PATH_MAX]) {
        int fd = safe_openat(rootfd, "etc/passwd", O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    FILE *stream = fdopen(fd, "r");
    if (stream == NULL) {
        close(fd);
        return -1;
    }
    char *line = NULL;
    size_t capacity = 0U;
    unsigned found = 0U;
    char expected_home[64];
    if (snprintf(expected_home, sizeof(expected_home), "/home/%s", account) >=
        (int)sizeof(expected_home)) {
        fclose(stream);
        return -1;
    }
    while (getline(&line, &capacity, stream) >= 0) {
        char *fields[7];
        size_t count = 0U;
        char *cursor = line;
        while (count < 7U) {
            fields[count++] = cursor;
            char *colon = strchr(cursor, ':');
            if (colon == NULL) break;
            *colon = '\0';
            cursor = colon + 1;
        }
        if (count != 7U || strchr(fields[6], ':') != NULL) continue;
        fields[6][strcspn(fields[6], "\r\n")] = '\0';
        uint32_t uid = 0U, gid = 0U;
        if (strcmp(fields[0], account) != 0) continue;
        if (parse_u32(fields[2], &uid) < 0 || parse_u32(fields[3], &gid) < 0 ||
            uid != 1000U || gid != 1000U ||
            strcmp(fields[5], expected_home) != 0 ||
            !valid_shell_path(fields[6]) || ++found != 1U) {
            found = UINT_MAX;
            break;
        }
        memcpy(shell, fields[6], strlen(fields[6]) + 1U);
    }
    free(line);
    fclose(stream);
    if (found != 1U) return -1;
    int shellfd = safe_openat(rootfd, shell + 1, O_RDONLY);
    if (shellfd < 0) return -1;
    struct stat shell_st;
    int valid = fstat(shellfd, &shell_st) == 0 && S_ISREG(shell_st.st_mode) &&
                (shell_st.st_mode & 0111) != 0;
    close(shellfd);
    return valid ? 0 : -1;
}

static int validate_rootfs(int rootfd, int homefd,
                           const struct authorized_session *session,
                           char shell[PATH_MAX], char *error,
                           size_t error_size) {
    struct stat root_st, home_st, mountpoint_st;
    struct statfs filesystem, home_filesystem;
    uint32_t user_id = session->uid_base + 1000U;
    if (fstat(rootfd, &root_st) < 0 || fstatfs(rootfd, &filesystem) < 0 ||
        !S_ISDIR(root_st.st_mode) || filesystem.f_type != EXT4_SUPER_MAGIC ||
        root_st.st_uid != session->uid_base || root_st.st_gid != user_id ||
        (root_st.st_mode & 07777) != 0710) {
        set_error(error, error_size, "user rootfs has unsafe filesystem ownership or type");
        return -1;
    }
    if (fstat(homefd, &home_st) < 0 || fstatfs(homefd, &home_filesystem) < 0 ||
        !S_ISDIR(home_st.st_mode) || home_st.st_uid != user_id ||
        home_st.st_gid != user_id || (home_st.st_mode & 07777) != 0700 ||
        home_filesystem.f_type != EXT4_SUPER_MAGIC || home_st.st_dev != root_st.st_dev) {
        set_error(error, error_size, "persistent home has unsafe ownership or mode");
        return -1;
    }
    char home_path[64];
    if (snprintf(home_path, sizeof(home_path), "home/%s", session->account) >=
        (int)sizeof(home_path)) {
        set_error(error, error_size, "user home path is too long");
        return -1;
    }
    int home_mountpoint = safe_openat(rootfd, home_path,
                                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (home_mountpoint < 0 || fstat(home_mountpoint, &mountpoint_st) < 0 ||
        mountpoint_st.st_uid != user_id || mountpoint_st.st_gid != user_id ||
        (mountpoint_st.st_mode & 0077) != 0) {
        if (home_mountpoint >= 0) close(home_mountpoint);
        set_error(error, error_size, "user rootfs home mountpoint is unsafe");
        return -1;
    }
    close(home_mountpoint);
    struct tree_scan scan = {
        .device = root_st.st_dev,
        .uid_base = session->uid_base,
        .entries = 0U,
        .error = error,
        .error_size = error_size,
    };
    if (reject_rootfs_submounts(session->account, error, error_size) < 0)
        return -1;
    if (scan_rootfs(rootfd, "", 0U, &scan) < 0) return -1;
    static const char *required_dirs[] = { "dev", "dev/pts", "proc", "run", "tmp" };
    for (size_t index = 0U; index < sizeof(required_dirs) / sizeof(required_dirs[0]); ++index) {
        int fd = safe_openat(rootfd, required_dirs[index],
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (fd < 0) {
            set_error(error, error_size, "user rootfs lacks a required mount directory");
            return -1;
        }
        close(fd);
    }
    static const char *required_devices[] = {
        "dev/console", "dev/null", "dev/tty", "dev/zero",
        "dev/random", "dev/urandom"
    };
    for (size_t index = 0U; index < sizeof(required_devices) / sizeof(required_devices[0]); ++index) {
        int fd = safe_openat(rootfd, required_devices[index], O_PATH | O_NOFOLLOW);
        struct stat device_st;
        int valid = fd >= 0 && fstat(fd, &device_st) == 0 &&
                    allowed_device(required_devices[index], &device_st);
        if (fd >= 0) close(fd);
        if (!valid) {
            set_error(error, error_size, "user rootfs lacks a required safe device node");
            return -1;
        }
    }
    if (read_user_shell(rootfd, session->account, shell) < 0) {
        set_error(error, error_size, "user rootfs account has no safe executable login shell");
        return -1;
    }
    return 0;
}

static int close_child_fds(void) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) == 0) return 0;
#endif
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0) return -1;
    rlim_t upper = limit.rlim_cur;
    if (upper == RLIM_INFINITY || upper > (rlim_t)INT_MAX)
        upper = (rlim_t)INT_MAX;
    for (rlim_t fd = 3U; fd < upper; ++fd) (void)close((int)fd);
    return 0;
}

static int run_capture(const char *path, char *const argv[],
                       char *output, size_t output_size) {
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0) return -1;
    pid_t child = fork();
    if (child < 0) {
        int saved = errno;
        close(pipefd[0]); close(pipefd[1]); errno = saved;
        return -1;
    }
    if (child == 0) {
        close(pipefd[0]);
        pid_t expected_parent = getppid();
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != expected_parent)
            _exit(126);
        int nullfd = open("/dev/null", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0 ||
            dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(nullfd, STDERR_FILENO) < 0)
            _exit(126);
        if (nullfd > STDERR_FILENO) close(nullfd);
        close(pipefd[1]);
        if (close_child_fds() < 0) _exit(126);
        char *const envp[] = { (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                               (char *)"LC_ALL=C", NULL };
        execve(path, argv, envp);
        _exit(127);
    }
    close(pipefd[1]);
    size_t used = 0U;
    int overflow = 0;
    for (;;) {
        char discard[256];
        int keep_output = output != NULL && output_size > used + 1U;
        char *target = keep_output ? output + used : discard;
        size_t available = keep_output ? output_size - used - 1U : sizeof(discard);
        ssize_t amount = read(pipefd[0], target, available);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) { overflow = 1; break; }
        if (amount == 0) break;
        if (keep_output) used += (size_t)amount;
        else if (output_size > 0U) overflow = 1;
    }
    close(pipefd[0]);
    if (output_size > 0U) output[used] = '\0';
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        return -1;
    }
    if (overflow || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static int consume_grant(const char *token, pid_t peer_pid,
                         struct authorized_session *session) {
    char pid_text[32];
    if (snprintf(pid_text, sizeof(pid_text), "%ld", (long)peer_pid) >=
        (int)sizeof(pid_text)) return -1;
    char *const argv[] = { (char *)GRANT_TOOL, (char *)"consume",
                           (char *)token, pid_text, NULL };
    char output[512];
    if (run_capture(GRANT_TOOL, argv, output, sizeof(output)) < 0) return -1;
    return parse_authorized(output, session);
}

static int provision_account(const char *account) {
    char *const argv[] = { (char *)PROVISIONER, (char *)"provision",
                           (char *)account, NULL };
    return run_capture(PROVISIONER, argv, NULL, 0U);
}

static int read_request(int fd, char *line, size_t capacity) {
    size_t used = 0U;
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) < 0) return -1;
    deadline.tv_sec += REQUEST_TIMEOUT_MS / 1000;
    deadline.tv_nsec += (long)(REQUEST_TIMEOUT_MS % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    while (used + 1U < capacity) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
        int64_t remaining = (int64_t)(deadline.tv_sec - now.tv_sec) * 1000 +
                            (deadline.tv_nsec - now.tv_nsec) / 1000000;
        if (remaining <= 0) { errno = ETIMEDOUT; return -1; }
        struct pollfd item = { .fd = fd, .events = POLLIN };
        int ready;
        do { ready = poll(&item, 1U, remaining > INT_MAX ? INT_MAX : (int)remaining); }
        while (ready < 0 && errno == EINTR);
        if (ready <= 0) { if (ready == 0) errno = ETIMEDOUT; return -1; }
        char value;
        ssize_t amount = read(fd, &value, 1U);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        line[used++] = value;
        if (value == '\n') {
            line[used] = '\0';
            return 0;
        }
    }
    errno = EMSGSIZE;
    return -1;
}

static int validate_peer_tty(const struct ucred *peer,
                             const struct authorized_session *session,
                             int *tty_fd_out) {
    char path[64];
    if (snprintf(path, sizeof(path), "/proc/%ld/fd/0", (long)peer->pid) >=
        (int)sizeof(path)) return -1;
    int ttyfd = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (ttyfd < 0) return -1;
    struct stat st;
    pid_t sid = getsid(peer->pid);
    int terminal_sid = 0;
    if (fstat(ttyfd, &st) < 0 || !S_ISCHR(st.st_mode) ||
        (uint32_t)major(st.st_rdev) != session->tty_major ||
        (uint32_t)minor(st.st_rdev) != session->tty_minor ||
        sid != session->session_id ||
        ioctl(ttyfd, TIOCGSID, &terminal_sid) < 0 ||
        terminal_sid != session->session_id) {
        close(ttyfd);
        errno = EACCES;
        return -1;
    }
    *tty_fd_out = ttyfd;
    return 0;
}

static int ensure_run_dir(void) {
    if (mkdir(RUN_DIR, 0755) < 0 && errno != EEXIST) return -1;
    struct stat st;
    if (lstat(RUN_DIR, &st) < 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0U || (st.st_mode & 0022) != 0U) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int bind_directory_fd(int fd, const char *target) {
    char source[64];
    int length = snprintf(source, sizeof(source), "/proc/self/fd/%d", fd);
    if (length < 0 || length >= (int)sizeof(source)) { errno = EINVAL; return -1; }
    return mount(source, target, NULL, MS_BIND, NULL);
}

static int fill_random(unsigned char *buffer, size_t length) {
    size_t used = 0U;
    while (used < length) {
        ssize_t amount = getrandom(buffer + used, length - used, 0);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        used += (size_t)amount;
    }
    return 0;
}

static int prepare_pins(int rootfd, int homefd, uint32_t uid_base,
                        char *pin_dir,
                        size_t pin_dir_size) {
    unsigned char random[8];
    if (fill_random(random, sizeof(random)) < 0) return -1;
    uint64_t nonce = 0U;
    memcpy(&nonce, random, sizeof(nonce));
    memset(random, 0, sizeof(random));
    if (snprintf(pin_dir, pin_dir_size, RUN_DIR "/pin-%ld-%016llx",
                 (long)getpid(), (unsigned long long)nonce) >=
        (int)pin_dir_size) { errno = ENAMETOOLONG; return -1; }
    if (mkdir(pin_dir, 0711) < 0) return -1;
    char root_pin[PATH_MAX], home_pin[PATH_MAX], bootstrap[PATH_MAX];
    if (snprintf(root_pin, sizeof(root_pin), "%s/rootfs", pin_dir) >= (int)sizeof(root_pin) ||
        snprintf(home_pin, sizeof(home_pin), "%s/home", pin_dir) >= (int)sizeof(home_pin) ||
        snprintf(bootstrap, sizeof(bootstrap), "%s/bootstrap", pin_dir) >= (int)sizeof(bootstrap))
        return -1;
    if (mkdir(root_pin, 0711) < 0 || mkdir(home_pin, 0711) < 0 ||
        mkdir(bootstrap, 0711) < 0 ||
        chown(bootstrap, (uid_t)uid_base, (gid_t)uid_base) < 0 ||
        chmod(bootstrap, 0700) < 0 ||
        bind_directory_fd(rootfd, root_pin) < 0 ||
        bind_directory_fd(homefd, home_pin) < 0) {
        int saved = errno;
        (void)umount2(home_pin, MNT_DETACH);
        (void)umount2(root_pin, MNT_DETACH);
        (void)rmdir(home_pin); (void)rmdir(root_pin); (void)rmdir(bootstrap);
        (void)rmdir(pin_dir); errno = saved;
        return -1;
    }
    return 0;
}

static void cleanup_pins(const char *pin_dir) {
    char root_pin[PATH_MAX], home_pin[PATH_MAX], bootstrap[PATH_MAX];
    if (snprintf(root_pin, sizeof(root_pin), "%s/rootfs", pin_dir) >= (int)sizeof(root_pin) ||
        snprintf(home_pin, sizeof(home_pin), "%s/home", pin_dir) >= (int)sizeof(home_pin) ||
        snprintf(bootstrap, sizeof(bootstrap), "%s/bootstrap", pin_dir) >= (int)sizeof(bootstrap))
        return;
    (void)umount2(home_pin, MNT_DETACH);
    (void)umount2(root_pin, MNT_DETACH);
    (void)rmdir(home_pin); (void)rmdir(root_pin); (void)rmdir(bootstrap);
    (void)rmdir(pin_dir);
}

static void install_map(pid_t pid, const char *name, const char *value) {
    char path[96];
    if (snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, name) >=
        (int)sizeof(path)) _exit(126);
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || write_all(fd, value, strlen(value)) < 0 || close(fd) < 0)
        _exit(126);
}

static int wait_byte(int fd, char expected, int timeout_ms) {
    struct pollfd item = { .fd = fd, .events = POLLIN };
    int result;
    do { result = poll(&item, 1U, timeout_ms); } while (result < 0 && errno == EINTR);
    char value = 0;
    return result > 0 && read(fd, &value, 1U) == 1 && value == expected ? 0 : -1;
}

static void child_fail(const char *message) {
    dprintf(STDERR_FILENO, "veyra-session-manager: session launch failed: %s: %s\n",
            message, strerror(errno));
    _exit(1);
}

struct launcher_args {
    int map_ready_write;
    int map_go_read;
    int rootfd;
    int homefd;
    int tty_slave;
    int session_ready_write;
    uint32_t uid_base;
    pid_t expected_parent;
    char account[MAX_ACCOUNT + 1U];
    char shell[PATH_MAX];
    char term[65];
    char pin_dir[PATH_MAX];
};

static void inner_session(struct launcher_args *args) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 ||
        getppid() != args->expected_parent)
        _exit(1);
    if (setsid() < 0 || ioctl(args->tty_slave, TIOCSCTTY, 0) < 0 ||
        tcsetpgrp(args->tty_slave, getpgrp()) < 0)
        child_fail("claim private terminal");
    if (dup2(args->tty_slave, STDIN_FILENO) < 0 ||
        dup2(args->tty_slave, STDOUT_FILENO) < 0 ||
        dup2(args->tty_slave, STDERR_FILENO) < 0)
        child_fail("attach private terminal");
    if (args->tty_slave > STDERR_FILENO) close(args->tty_slave);
    if (sethostname("veyra-user", 10U) < 0 ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        child_fail("isolate mount propagation");
    char bootstrap[PATH_MAX], newroot[PATH_MAX], oldroot[PATH_MAX];
    char pin_root[PATH_MAX], pin_home[PATH_MAX], home_target[PATH_MAX];
    if (snprintf(bootstrap, sizeof(bootstrap), "%s/bootstrap", args->pin_dir) >= (int)sizeof(bootstrap) ||
        snprintf(newroot, sizeof(newroot), "%s/root", bootstrap) >= (int)sizeof(newroot) ||
        snprintf(pin_root, sizeof(pin_root), "%s/rootfs", args->pin_dir) >= (int)sizeof(pin_root) ||
        snprintf(pin_home, sizeof(pin_home), "%s/home", args->pin_dir) >= (int)sizeof(pin_home) ||
        snprintf(home_target, sizeof(home_target), "%s/home/%s", newroot, args->account) >= (int)sizeof(home_target))
        child_fail("format private root paths");
    struct stat bootstrap_st;
    if (lstat(bootstrap, &bootstrap_st) < 0 || !S_ISDIR(bootstrap_st.st_mode) ||
        bootstrap_st.st_uid != 0U || (bootstrap_st.st_mode & 0022) != 0U)
        child_fail("validate private root staging directory");
    if (mount("tmpfs", bootstrap, "tmpfs", MS_NOSUID | MS_NODEV,
              "mode=0700,size=16m") < 0 || mkdir(newroot, 0700) < 0)
        child_fail("create private root staging filesystem");
    if (mount(pin_root, newroot, NULL, MS_BIND, NULL) < 0)
        child_fail("attach validated user rootfs");
    if (mount(pin_home, home_target, NULL, MS_BIND, NULL) < 0)
        child_fail("attach persistent user home");
    if (mount(NULL, home_target, NULL,
              MS_BIND | MS_REMOUNT | MS_NODEV | MS_NOSUID, NULL) < 0)
        child_fail("restrict persistent user home mount");
    char old_name[96];
    unsigned char nonce_bytes[8];
    if (fill_random(nonce_bytes, sizeof(nonce_bytes)) < 0) child_fail("generate root marker");
    uint64_t nonce = 0U;
    memcpy(&nonce, nonce_bytes, sizeof(nonce));
    memset(nonce_bytes, 0, sizeof(nonce_bytes));
    if (snprintf(old_name, sizeof(old_name), ".veyra-oldroot-%016llx",
                 (unsigned long long)nonce) >= (int)sizeof(old_name) ||
        snprintf(oldroot, sizeof(oldroot), "%s/%s", newroot, old_name) >= (int)sizeof(oldroot))
        child_fail("format old-root path");
    if (mkdir(oldroot, 0700) < 0) child_fail("prepare old-root mountpoint");
    if (args->homefd >= 0) close(args->homefd);
    if (args->rootfd >= 0) close(args->rootfd);
    if (chdir(bootstrap) < 0 || chroot(bootstrap) < 0 || chdir("/") < 0 ||
        syscall(SYS_pivot_root, "/root", oldroot + strlen(bootstrap)) < 0)
        child_fail("enter isolated user rootfs");
    if (chdir("/") < 0 || umount2(old_name, MNT_DETACH) < 0 || rmdir(old_name) < 0)
        child_fail("detach system root");
    if (mount("proc", "/proc", "proc", MS_NODEV | MS_NOSUID | MS_NOEXEC, "") < 0 ||
        mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC,
              "newinstance,ptmxmode=0666,mode=0600,uid=1000,gid=1000") < 0 ||
        mount("tmpfs", "/run", "tmpfs", MS_NODEV | MS_NOSUID, "mode=0755,size=32m") < 0 ||
        mount("tmpfs", "/tmp", "tmpfs", MS_NODEV | MS_NOSUID, "mode=1777,size=256m") < 0)
        child_fail("mount user-private runtime filesystems");
    if (chdir("/home") < 0 || chdir(args->account) < 0)
        child_fail("enter persistent home");
    if (setgid(1000U) < 0 || setuid(1000U) < 0)
        child_fail("drop to the user account");
    (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    if (close_child_fds() < 0) child_fail("close inherited system descriptors");
    char argv0[PATH_MAX];
    const char *base = strrchr(args->shell, '/');
    base = base == NULL ? args->shell : base + 1;
    if (snprintf(argv0, sizeof(argv0), "-%s", base) >= (int)sizeof(argv0))
        child_fail("format login shell name");
    char *const shell_argv[] = { argv0, NULL };
    char home_env[80], user_env[48], logname_env[48], shell_env[PATH_MAX];
    char term_env[72];
    if (snprintf(home_env, sizeof(home_env), "HOME=/home/%s", args->account) >= (int)sizeof(home_env) ||
        snprintf(user_env, sizeof(user_env), "USER=%s", args->account) >= (int)sizeof(user_env) ||
        snprintf(logname_env, sizeof(logname_env), "LOGNAME=%s", args->account) >= (int)sizeof(logname_env) ||
        snprintf(shell_env, sizeof(shell_env), "SHELL=%s", args->shell) >= (int)sizeof(shell_env) ||
        snprintf(term_env, sizeof(term_env), "TERM=%s", args->term) >= (int)sizeof(term_env))
        child_fail("format user environment");
    char *const envp[] = { home_env, user_env, logname_env, shell_env,
                           term_env, (char *)"PATH=/usr/local/bin:/usr/bin:/bin",
                           (char *)"TMPDIR=/tmp", (char *)"LANG=C.UTF-8", NULL };
    if (write_all(args->session_ready_write, "R", 1U) < 0)
        child_fail("signal session readiness");
    close(args->session_ready_write);
    execve(args->shell, shell_argv, envp);
    child_fail("start user login shell");
}

static void namespace_launcher(struct launcher_args *args) {
    if (setgroups(0U, NULL) < 0 || setgid((gid_t)args->uid_base) < 0 ||
        setuid((uid_t)args->uid_base) < 0 ||
        prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 ||
        getppid() != args->expected_parent || unshare(CLONE_NEWUSER) < 0)
        child_fail("create mapped user namespace");
    if (write_all(args->map_ready_write, "U", 1U) < 0) _exit(1);
    close(args->map_ready_write);
    if (wait_byte(args->map_go_read, 'G', 10000) < 0) _exit(1);
    close(args->map_go_read);
    if (geteuid() != 0U || getegid() != 0U ||
        prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 ||
        getppid() != args->expected_parent ||
        unshare(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC |
                CLONE_NEWUTS | CLONE_NEWPID) < 0)
        child_fail("create isolated namespaces");
    pid_t pid1 = fork();
    if (pid1 < 0) child_fail("start namespace process");
    if (pid1 == 0) inner_session(args);
    close(args->tty_slave);
    close(args->rootfd);
    if (args->homefd >= 0) close(args->homefd);
    int status = 0;
    while (waitpid(pid1, &status, 0) < 0) {
        if (errno == EINTR) continue;
        _exit(1);
    }
    if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
    if (WIFSIGNALED(status)) _exit(128 + WTERMSIG(status));
    _exit(1);
}

static int open_account_root(const struct authorized_session *session,
                             int *rootfd, int *homefd) {
    int usersfd = open(USERS_PATH, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (usersfd < 0) return -1;
    int accountfd = openat(usersfd, session->account,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(usersfd);
    if (accountfd < 0) return -1;
    struct stat account_st;
    if (fstat(accountfd, &account_st) < 0 || account_st.st_uid != 0U ||
        account_st.st_gid != 0U || (account_st.st_mode & 07777) != 0700) {
        close(accountfd); errno = EPERM; return -1;
    }
    *rootfd = openat(accountfd, "rootfs",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    *homefd = openat(accountfd, "home",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(accountfd);
    if (*rootfd < 0 || *homefd < 0) {
        if (*rootfd >= 0) close(*rootfd);
        if (*homefd >= 0) close(*homefd);
        return -1;
    }
    return 0;
}

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

struct pending_buffer {
    unsigned char bytes[RELAY_BUFFER];
    size_t start;
    size_t length;
};

static int queue_read(int fd, struct pending_buffer *buffer) {
    if (buffer->start > 0U && buffer->length > 0U) {
        memmove(buffer->bytes, buffer->bytes + buffer->start, buffer->length);
        buffer->start = 0U;
    } else if (buffer->length == 0U) buffer->start = 0U;
    size_t available = sizeof(buffer->bytes) - buffer->start - buffer->length;
    if (available == 0U) return 0;
    ssize_t amount = read(fd, buffer->bytes + buffer->start + buffer->length, available);
    if (amount < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
    if (amount < 0) return -1;
    if (amount == 0) return 1;
    buffer->length += (size_t)amount;
    return 0;
}

static int queue_write(int fd, struct pending_buffer *buffer) {
    if (buffer->length == 0U) return 0;
    ssize_t amount = write(fd, buffer->bytes + buffer->start, buffer->length);
    if (amount < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
    if (amount <= 0) return -1;
    buffer->start += (size_t)amount;
    buffer->length -= (size_t)amount;
    if (buffer->length == 0U) buffer->start = 0U;
    return 0;
}

static int relay_session(int socket_fd, int master_fd, int tty_fd, pid_t launcher) {
    if (set_nonblock(socket_fd) < 0 || set_nonblock(master_fd) < 0) return -1;
    int launcher_pidfd = (int)syscall(SYS_pidfd_open, launcher, 0U);
    if (launcher_pidfd < 0) return -1;
    struct pending_buffer input = {0}, output = {0};
    int socket_eof = 0, pty_eof = 0, result = 0;
    struct winsize previous = {0};
    if (ioctl(tty_fd, TIOCGWINSZ, &previous) == 0)
        (void)ioctl(master_fd, TIOCSWINSZ, &previous);
    while (!socket_eof && (!pty_eof || output.length > 0U)) {
        struct pollfd fds[3];
        fds[0] = (struct pollfd){ .fd = socket_fd,
            .events = (short)((socket_eof || input.length == sizeof(input.bytes) ? 0 : POLLIN) |
                              (output.length > 0U ? POLLOUT : 0)) };
        fds[1] = (struct pollfd){ .fd = master_fd,
            .events = (short)((pty_eof || output.length == sizeof(output.bytes) ? 0 : POLLIN) |
                              (input.length > 0U ? POLLOUT : 0)) };
        fds[2] = (struct pollfd){ .fd = launcher_pidfd, .events = POLLIN };
        int ready;
        do { ready = poll(fds, 3U, 500); } while (ready < 0 && errno == EINTR);
        if (ready < 0) { result = -1; break; }
        struct winsize current = {0};
        if (ioctl(tty_fd, TIOCGWINSZ, &current) == 0 &&
            (current.ws_row != previous.ws_row || current.ws_col != previous.ws_col ||
             current.ws_xpixel != previous.ws_xpixel || current.ws_ypixel != previous.ws_ypixel)) {
            previous = current;
            (void)ioctl(master_fd, TIOCSWINSZ, &current);
        }
        if ((fds[0].revents & POLLIN) != 0 && queue_read(socket_fd, &input) == 1)
            socket_eof = 1;
        else if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
            socket_eof = 1;
        if ((fds[1].revents & POLLIN) != 0) {
            int read_result = queue_read(master_fd, &output);
            if (read_result == 1 || (read_result < 0 && errno == EIO)) pty_eof = 1;
            else if (read_result < 0) { result = -1; break; }
        } else if ((fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            pty_eof = 1;
        }
        if (input.length > 0U && queue_write(master_fd, &input) < 0) {
            if (errno == EIO || errno == EPIPE) pty_eof = 1;
            else { result = -1; break; }
        }
        if (output.length > 0U && queue_write(socket_fd, &output) < 0) {
            if (errno == EPIPE || errno == ECONNRESET) socket_eof = 1;
            else { result = -1; break; }
        }
        if ((fds[2].revents & POLLIN) != 0) {
            close(launcher_pidfd);
            launcher_pidfd = -1;
        }
    }
    if (launcher_pidfd >= 0) close(launcher_pidfd);
    if (socket_eof) return 1;
    return result;
}

static int create_namespace_session(int socket_fd, int tty_fd,
                                   const struct authorized_session *session,
                                   const char *term, int rootfd, int homefd,
                                   const char *shell) {
    int master = -1, slave = -1;
    master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0) goto fail;
    char slave_name[PATH_MAX];
    if (ptsname_r(master, slave_name, sizeof(slave_name)) != 0) goto fail;
    slave = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) goto fail;
    struct winsize window = {0};
    if (ioctl(tty_fd, TIOCGWINSZ, &window) == 0)
        (void)ioctl(slave, TIOCSWINSZ, &window);

    char error[256] = {0};
    char checked_shell[PATH_MAX] = {0};
    if (validate_rootfs(rootfd, homefd, session, checked_shell,
                        error, sizeof(error)) < 0 ||
        strcmp(checked_shell, shell) != 0) {
        fprintf(stderr, "veyra-session-manager: refused rootfs for %s: %s\n",
                session->account, error[0] ? error : "shell changed during validation");
        goto fail;
    }
    if (unshare(CLONE_NEWNS) < 0 || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        goto fail;
    char pin_dir[PATH_MAX];
    if (prepare_pins(rootfd, homefd, session->uid_base,
                     pin_dir, sizeof(pin_dir)) < 0) goto fail;
    int map_ready[2], map_go[2], session_ready[2];
    if (pipe2(map_ready, O_CLOEXEC) < 0 || pipe2(map_go, O_CLOEXEC) < 0 ||
        pipe2(session_ready, O_CLOEXEC) < 0) {
        cleanup_pins(pin_dir);
        goto fail;
    }
    pid_t expected_parent = getpid();
    pid_t launcher = fork();
    if (launcher < 0) {
        close(map_ready[0]); close(map_ready[1]); close(map_go[0]); close(map_go[1]);
        close(session_ready[0]); close(session_ready[1]);
        cleanup_pins(pin_dir);
        goto fail;
    }
    if (launcher == 0) {
        close(map_ready[0]); close(map_go[1]); close(session_ready[0]);
        close(master);
        struct launcher_args args = {
            .map_ready_write = map_ready[1], .map_go_read = map_go[0],
            .rootfd = rootfd, .homefd = homefd, .tty_slave = slave,
            .session_ready_write = session_ready[1], .uid_base = session->uid_base,
            .expected_parent = expected_parent,
        };
        memcpy(args.account, session->account, strlen(session->account) + 1U);
        memcpy(args.shell, shell, strlen(shell) + 1U);
        memcpy(args.term, term, strlen(term) + 1U);
        memcpy(args.pin_dir, pin_dir, strlen(pin_dir) + 1U);
        namespace_launcher(&args);
        _exit(1);
    }
    close(map_ready[1]); close(map_go[0]); close(session_ready[1]); close(slave);
    if (wait_byte(map_ready[0], 'U', 10000) < 0) {
        close(map_ready[0]); close(map_go[1]); close(session_ready[0]);
        (void)kill(launcher, SIGKILL); (void)waitpid(launcher, NULL, 0);
        cleanup_pins(pin_dir); close(master); return -1;
    }
    close(map_ready[0]);
    char uid_map[64], gid_map[64];
    if (snprintf(uid_map, sizeof(uid_map), "0 %u %u\n", session->uid_base, MAP_LENGTH) >= (int)sizeof(uid_map) ||
        snprintf(gid_map, sizeof(gid_map), "0 %u %u\n", session->uid_base, MAP_LENGTH) >= (int)sizeof(gid_map)) {
        close(map_go[1]); close(session_ready[0]);
        (void)kill(launcher, SIGKILL); (void)waitpid(launcher, NULL, 0);
        cleanup_pins(pin_dir); close(master); errno = EOVERFLOW; return -1;
    }
    char proc_path[96];
    if (snprintf(proc_path, sizeof(proc_path), "/proc/%ld/setgroups", (long)launcher) >= (int)sizeof(proc_path)) {
        close(map_go[1]); close(session_ready[0]);
        (void)kill(launcher, SIGKILL); (void)waitpid(launcher, NULL, 0);
        cleanup_pins(pin_dir); close(master); errno = EOVERFLOW; return -1;
    }
    int setgroups_fd = open(proc_path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (setgroups_fd < 0 || write_all(setgroups_fd, "deny\n", 5U) < 0 || close(setgroups_fd) < 0) {
        close(map_go[1]); close(session_ready[0]);
        (void)kill(launcher, SIGKILL); (void)waitpid(launcher, NULL, 0);
        cleanup_pins(pin_dir); close(master); return -1;
    }
    install_map(launcher, "uid_map", uid_map);
    install_map(launcher, "gid_map", gid_map);
    if (write_all(map_go[1], "G", 1U) < 0) {
        close(map_go[1]); close(session_ready[0]);
        (void)kill(launcher, SIGKILL); (void)waitpid(launcher, NULL, 0);
        cleanup_pins(pin_dir); close(master); return -1;
    }
    close(map_go[1]);
    int ready_result = wait_byte(session_ready[0], 'R', 15000);
    close(session_ready[0]);
    if (ready_result < 0) {
        (void)kill(launcher, SIGKILL); (void)waitpid(launcher, NULL, 0);
        cleanup_pins(pin_dir); close(master); return -1;
    }
    if (write_all(socket_fd, "OK\n", 3U) < 0) {
        (void)kill(launcher, SIGTERM);
        (void)waitpid(launcher, NULL, 0);
        cleanup_pins(pin_dir); close(master); return -1;
    }
    int relay_result = relay_session(socket_fd, master, tty_fd, launcher);
    if (relay_result != 0) (void)kill(launcher, SIGTERM);
    int status = 0;
    while (waitpid(launcher, &status, 0) < 0 && errno == EINTR) {}
    cleanup_pins(pin_dir);
    close(master);
    return relay_result;
fail:
    if (slave >= 0) close(slave);
    if (master >= 0) close(master);
    return -1;
}

static int handle_session_client(int fd) {
    struct ucred peer;
    socklen_t peer_length = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_length) < 0 ||
        peer.pid <= 1) {
        (void)write_all(fd, "ERROR permission\n", 17U);
        return -1;
    }
    char request[LINE_LIMIT] = {0};
    char token[TOKEN_LENGTH + 1U] = {0}, term[65] = {0};
    if (read_request(fd, request, sizeof(request)) < 0 ||
        parse_request(request, token, term) < 0) {
        (void)write_all(fd, "ERROR protocol\n", 15U);
        return -1;
    }
    memset(request, 0, sizeof(request));
    struct authorized_session session = {0};
    if (consume_grant(token, peer.pid, &session) < 0) {
        memset(token, 0, sizeof(token));
        (void)write_all(fd, "ERROR authentication\n", 21U);
        return -1;
    }
    memset(token, 0, sizeof(token));
    int tty_fd = -1;
    if (validate_peer_tty(&peer, &session, &tty_fd) < 0) {
        (void)write_all(fd, "ERROR terminal\n", 15U);
        return -1;
    }
    if (provision_account(session.account) < 0) {
        close(tty_fd);
        (void)write_all(fd, "ERROR provisioning\n", 19U);
        return -1;
    }
    int rootfd = -1, homefd = -1;
    if (open_account_root(&session, &rootfd, &homefd) < 0) {
        close(tty_fd);
        (void)write_all(fd, "ERROR user-root\n", 16U);
        return -1;
    }
    char shell[PATH_MAX] = {0}, error[256] = {0};
    if (validate_rootfs(rootfd, homefd, &session, shell, error, sizeof(error)) < 0) {
        close(rootfd); close(homefd); close(tty_fd);
        fprintf(stderr, "veyra-session-manager: refused rootfs for %s: %s\n",
                session.account, error);
        (void)write_all(fd, "ERROR user-root\n", 16U);
        return -1;
    }
    int result = create_namespace_session(fd, tty_fd, &session, term,
                                          rootfd, homefd, shell);
    close(rootfd); close(homefd); close(tty_fd);
    if (result < 0) {
        (void)write_all(fd, "ERROR launch\n", 13U);
        return -1;
    }
    return 0;
}

static int prepare_socket(int *listener_out) {
    if (ensure_run_dir() < 0) return -1;
    struct stat st;
    if (lstat(SOCKET_PATH, &st) == 0) {
        if (!S_ISSOCK(st.st_mode) || st.st_uid != 0U) { errno = EPERM; return -1; }
        int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un old_address = { .sun_family = AF_UNIX };
        (void)snprintf(old_address.sun_path, sizeof(old_address.sun_path), "%s", SOCKET_PATH);
        int active = probe >= 0 && connect(probe, (struct sockaddr *)&old_address,
                                           sizeof(old_address)) == 0;
        if (probe >= 0) close(probe);
        if (active) { errno = EADDRINUSE; return -1; }
        if (unlink(SOCKET_PATH) < 0) return -1;
    } else if (errno != ENOENT) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s", SOCKET_PATH) >=
        (int)sizeof(address.sun_path) ||
        bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        chmod(SOCKET_PATH, 0666) < 0 || listen(fd, 32) < 0) {
        int saved = errno;
        close(fd); (void)unlink(SOCKET_PATH); errno = saved;
        return -1;
    }
    *listener_out = fd;
    return 0;
}

static void request_stop(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static void reap_workers(void) {
    int status;
    while (waitpid(-1, &status, WNOHANG) > 0) {
        if (active_workers > 0U) active_workers--;
    }
}

static int serve(void) {
    if (geteuid() != 0U || ensure_run_dir() < 0) { errno = EPERM; return 1; }
    int listener = -1;
    if (prepare_socket(&listener) < 0) return 1;
    struct sigaction action = {0};
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGTERM, &action, NULL);
    (void)sigaction(SIGINT, &action, NULL);
    (void)signal(SIGPIPE, SIG_IGN);
    puts("veyra-session-manager: listening");
    fflush(stdout);
    while (!stopping) {
        struct pollfd item = { .fd = listener, .events = POLLIN };
        int result;
        do { result = poll(&item, 1U, 500); } while (result < 0 && errno == EINTR);
        if (result < 0) break;
        reap_workers();
        if (result == 0 || (item.revents & POLLIN) == 0) continue;
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }
        if (active_workers >= MAX_SESSION_WORKERS) {
            (void)write_all(client, "ERROR busy\n", 11U);
            close(client);
            continue;
        }
        pid_t parent = getpid();
        pid_t worker = fork();
        if (worker == 0) {
            close(listener);
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent)
                _exit(1);
            int result = handle_session_client(client);
            close(client);
            _exit(result == 0 ? 0 : 1);
        }
        close(client);
        if (worker < 0) perror("veyra-session-manager: fork");
        else active_workers++;
    }
    close(listener);
    (void)unlink(SOCKET_PATH);
    reap_workers();
    return 0;
}

static void clear_pam_responses(struct pam_response *responses, int count) {
    if (responses == NULL) return;
    for (int index = 0; index < count; ++index) {
        if (responses[index].resp != NULL) {
            memset(responses[index].resp, 0, strlen(responses[index].resp));
            free(responses[index].resp);
        }
    }
    free(responses);
}

static int read_pam_line(int tty_fd, int echo, char **answer) {
    char input[1024];
    size_t used = 0U;
    int too_long = 0;
    struct termios original, hidden;
    int changed = 0;
    if (!echo) {
        if (tcgetattr(tty_fd, &original) < 0) return -1;
        hidden = original;
        hidden.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(tty_fd, TCSAFLUSH, &hidden) < 0) return -1;
        changed = 1;
    }
    for (;;) {
        char value;
        ssize_t amount = read(tty_fd, &value, 1U);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) {
            if (changed) (void)tcsetattr(tty_fd, TCSAFLUSH, &original);
            memset(input, 0, sizeof(input));
            return -1;
        }
        if (value == '\n' || value == '\r') break;
        if (used + 1U < sizeof(input)) input[used++] = value;
        else too_long = 1;
    }
    if (changed) (void)tcsetattr(tty_fd, TCSAFLUSH, &original);
    if (!echo) (void)write_all(tty_fd, "\n", 1U);
    if (too_long) {
        memset(input, 0, sizeof(input));
        errno = EOVERFLOW;
        return -1;
    }
    input[used] = '\0';
    *answer = strdup(input);
    memset(input, 0, sizeof(input));
    return *answer == NULL ? -1 : 0;
}

static int login_conversation(int message_count,
                              const struct pam_message **messages,
                              struct pam_response **responses, void *data) {
    int tty_fd = *(const int *)data;
    if (message_count <= 0 || messages == NULL || responses == NULL || tty_fd < 0)
        return PAM_CONV_ERR;
    struct pam_response *result = calloc((size_t)message_count, sizeof(*result));
    if (result == NULL) return PAM_BUF_ERR;
    for (int index = 0; index < message_count; ++index) {
        const struct pam_message *message = messages[index];
        if (message == NULL || message->msg == NULL) goto error;
        switch (message->msg_style) {
        case PAM_PROMPT_ECHO_ON:
            if (write_all(tty_fd, message->msg, strlen(message->msg)) < 0 ||
                read_pam_line(tty_fd, 1, &result[index].resp) < 0)
                goto error;
            break;
        case PAM_PROMPT_ECHO_OFF:
            if (write_all(tty_fd, message->msg, strlen(message->msg)) < 0 ||
                read_pam_line(tty_fd, 0, &result[index].resp) < 0)
                goto error;
            break;
        case PAM_TEXT_INFO:
            if (write_all(tty_fd, message->msg, strlen(message->msg)) < 0 ||
                write_all(tty_fd, "\n", 1U) < 0)
                goto error;
            break;
        case PAM_ERROR_MSG:
            if (write_all(tty_fd, message->msg, strlen(message->msg)) < 0 ||
                write_all(tty_fd, "\n", 1U) < 0)
                goto error;
            break;
        default:
            goto error;
        }
        result[index].resp_retcode = 0;
    }
    *responses = result;
    return PAM_SUCCESS;

error:
    clear_pam_responses(result, message_count);
    return PAM_CONV_ERR;
}

static int login_frontend(void) {
    if (geteuid() != 0U) {
        fputs("veyra-login: must be started by the system login service\n", stderr);
        return 1;
    }
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fputs("veyra-login: an interactive terminal is required\n", stderr);
        return 1;
    }
    char tty_name[PATH_MAX];
    if (ttyname_r(STDIN_FILENO, tty_name, sizeof(tty_name)) != 0) {
        fputs("veyra-login: cannot identify the login terminal\n", stderr);
        return 1;
    }
    int tty_fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tty_fd < 0) {
        perror("veyra-login: open controlling terminal");
        return 1;
    }
    const char *term_value = getenv("TERM");
    char term[65];
    if (!valid_term(term_value)) term_value = "linux";
    memcpy(term, term_value, strlen(term_value) + 1U);
    if (clearenv() < 0 || setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) < 0 ||
        setenv("TERM", term, 1) < 0) {
        close(tty_fd);
        fputs("veyra-login: cannot sanitize the login environment\n", stderr);
        return 1;
    }
    struct pam_conv conversation = {
        .conv = login_conversation,
        .appdata_ptr = &tty_fd,
    };
    pam_handle_t *pamh = NULL;
    int status = pam_start("veyra-login", NULL, &conversation, &pamh);
    int credentials_established = 0;
    int session_open = 0;
    int result = 1;
    if (status != PAM_SUCCESS || pamh == NULL) {
        (void)write_all(tty_fd, "veyra-login: PAM initialization failed\n", 39U);
        if (pamh != NULL) (void)pam_end(pamh, status);
        close(tty_fd);
        return 1;
    }
    status = pam_set_item(pamh, PAM_TTY, tty_name);
    if (status == PAM_SUCCESS) status = pam_authenticate(pamh, 0);
    if (status == PAM_SUCCESS) status = pam_acct_mgmt(pamh, 0);
    if (status == PAM_SUCCESS) {
        status = pam_setcred(pamh, PAM_ESTABLISH_CRED);
        credentials_established = status == PAM_SUCCESS;
    }
    if (status == PAM_SUCCESS) {
        status = pam_open_session(pamh, 0);
        session_open = status == PAM_SUCCESS;
    }
    const char *account = NULL;
    if (status == PAM_SUCCESS) status = pam_get_user(pamh, &account, NULL);
    struct passwd entry, *found = NULL;
    char passwd_buffer[16384];
    if (status == PAM_SUCCESS && (!valid_account(account) ||
        getpwnam_r(account, &entry, passwd_buffer, sizeof(passwd_buffer), &found) != 0 ||
        found == NULL || found->pw_uid == 0U || found->pw_gid == 0U))
        status = PAM_USER_UNKNOWN;
    const char *grant = status == PAM_SUCCESS
        ? pam_getenv(pamh, "VEYRA_SESSION_TOKEN") : NULL;
    if (status == PAM_SUCCESS && !valid_token(grant)) status = PAM_SESSION_ERR;
    if (status == PAM_SUCCESS) {
        if (setresgid(found->pw_gid, 0U, 0U) < 0 ||
            setresuid(found->pw_uid, 0U, 0U) < 0) {
            status = PAM_SESSION_ERR;
        } else {
            if (setenv("VEYRA_SESSION_TOKEN", grant, 1) < 0) status = PAM_SESSION_ERR;
            else result = client_login();
        }
    }
    if (session_open) {
        int close_status = pam_close_session(pamh, 0);
        if (status == PAM_SUCCESS && close_status != PAM_SUCCESS) status = close_status;
    }
    if (credentials_established) {
        int delete_status = pam_setcred(pamh, PAM_DELETE_CRED);
        if (status == PAM_SUCCESS && delete_status != PAM_SUCCESS) status = delete_status;
    }
    (void)pam_putenv(pamh, "VEYRA_SESSION_TOKEN");
    if (status != PAM_SUCCESS) {
        const char *message = pam_strerror(pamh, status);
        const char prefix[] = "\nveyra-login: ";
        (void)write_all(tty_fd, prefix, sizeof(prefix) - 1U);
        if (message != NULL) (void)write_all(tty_fd, message, strlen(message));
        (void)write_all(tty_fd, "\n", 1U);
        result = 1;
    }
    (void)pam_end(pamh, status);
    close(tty_fd);
    return result;
}

static int client_login(void) {
    char *token_value = getenv("VEYRA_SESSION_TOKEN");
    if (token_value == NULL || !valid_token(token_value)) {
        fputs("veyra-login: no valid PAM session grant is present\n", stderr);
        return 1;
    }
    char token[TOKEN_LENGTH + 1U];
    memcpy(token, token_value, TOKEN_LENGTH + 1U);
    memset(token_value, 0, TOKEN_LENGTH);
    (void)unsetenv("VEYRA_SESSION_TOKEN");
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        memset(token, 0, sizeof(token));
        fputs("veyra-login: an interactive terminal is required\n", stderr);
        return 1;
    }
    const char *term_value = getenv("TERM");
    char term[65];
    if (!valid_term(term_value)) term_value = "linux";
    memcpy(term, term_value, strlen(term_value) + 1U);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("veyra-login: socket"); memset(token, 0, sizeof(token)); return 1; }
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s", SOCKET_PATH) >=
        (int)sizeof(address.sun_path) ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("veyra-login: connect session manager");
        close(fd); memset(token, 0, sizeof(token)); return 1;
    }
    char request[LINE_LIMIT];
    int length = snprintf(request, sizeof(request), "start %s %s\n", token, term);
    memset(token, 0, sizeof(token));
    if (length < 0 || length >= (int)sizeof(request) ||
        write_all(fd, request, (size_t)length) < 0) {
        close(fd); fputs("veyra-login: could not submit login grant\n", stderr); return 1;
    }
    memset(request, 0, sizeof(request));
    char response[128] = {0};
    size_t used = 0U;
    while (used + 1U < sizeof(response)) {
        ssize_t amount = read(fd, response + used, 1U);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) { close(fd); fputs("veyra-login: manager closed the connection\n", stderr); return 1; }
        if (response[used++] == '\n') break;
    }
    response[used] = '\0';
    if (strcmp(response, "OK\n") != 0) {
        response[strcspn(response, "\r\n")] = '\0';
        fprintf(stderr, "veyra-login: %s\n", response[0] ? response : "session rejected");
        close(fd); return 1;
    }
    struct termios original, raw;
    if (tcgetattr(STDIN_FILENO, &original) < 0) {
        close(fd); perror("veyra-login: terminal settings"); return 1;
    }
    raw = original;
    cfmakeraw(&raw);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0) {
        close(fd); perror("veyra-login: raw terminal mode"); return 1;
    }
    if (set_nonblock(fd) < 0) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
        close(fd); perror("veyra-login: nonblocking socket"); return 1;
    }
    struct pending_buffer input = {0}, output = {0};
    int input_eof = 0, socket_eof = 0, write_shutdown = 0;
    while (!input_eof || !socket_eof || output.length > 0U) {
        struct pollfd fds[2] = {
            { .fd = STDIN_FILENO, .events = (short)(input_eof || input.length == sizeof(input.bytes) ? 0 : POLLIN) },
            { .fd = fd, .events = (short)((socket_eof || output.length == sizeof(output.bytes) ? 0 : POLLIN) |
                                          (input.length > 0U ? POLLOUT : 0)) }
        };
        int result;
        do { result = poll(fds, 2U, -1); } while (result < 0 && errno == EINTR);
        if (result < 0) break;
        if ((fds[0].revents & POLLIN) != 0 && queue_read(STDIN_FILENO, &input) == 1)
            input_eof = 1;
        else if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) input_eof = 1;
        if ((fds[1].revents & POLLIN) != 0 && queue_read(fd, &output) == 1)
            socket_eof = 1;
        else if ((fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) socket_eof = 1;
        if (input.length > 0U && queue_write(fd, &input) < 0) socket_eof = 1;
        if (output.length > 0U && queue_write(STDOUT_FILENO, &output) < 0) input_eof = 1;
        if (input_eof && input.length == 0U && !write_shutdown) {
            (void)shutdown(fd, SHUT_WR);
            write_shutdown = 1;
        }
        if (socket_eof) { output.length = 0U; break; }
    }
    (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
    close(fd);
    return 0;
}

static int self_test(void) {
    char request[] = "start 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef xterm-256color\n";
    char token[TOKEN_LENGTH + 1U], term[65];
    if (parse_request(request, token, term) < 0 || strcmp(term, "xterm-256color") != 0) {
        fputs("self-test: valid request was rejected\n", stderr);
        return 1;
    }
    char bad_request[] = "start 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;id xterm\n";
    if (parse_request(bad_request, token, term) == 0) {
        fputs("self-test: malformed request was accepted\n", stderr);
        return 1;
    }
    char record[] = "authorized\tveyratest\t23150\t23150\t300000\t42\t136\t7\n";
    struct authorized_session session = {0};
    if (parse_authorized(record, &session) < 0 ||
        strcmp(session.account, "veyratest") != 0 || session.uid_base != 300000U ||
        session.session_id != 42 || session.tty_major != 136U || session.tty_minor != 7U) {
        fputs("self-test: valid authorization record was rejected\n", stderr);
        return 1;
    }
    char bad_record[] = "authorized\tveyratest\t23150\t23150\t300000\t42\t136\t7\textra\n";
    if (parse_authorized(bad_record, &session) == 0) {
        fputs("self-test: malformed authorization record was accepted\n", stderr);
        return 1;
    }
    char *const discard_argv[] = {
        (char *)"/bin/sh", (char *)"-c", (char *)"printf ok", NULL
    };
    if (run_capture("/bin/sh", discard_argv, NULL, 0U) < 0) {
        fputs("self-test: bounded subprocess output discard failed\n", stderr);
        return 1;
    }
    puts("session manager protocol checks passed");
    return 0;
}

int main(int argc, char **argv) {
    const char *base = strrchr(argv[0], '/');
    base = base == NULL ? argv[0] : base + 1;
    if (strcmp(base, "veyra-session-login") == 0) return client_login();
    if (strcmp(base, "veyra-login") == 0) return login_frontend();
    if (argc == 2 && strcmp(argv[1], "self-test") == 0) return self_test();
    if (argc == 2 && strcmp(argv[1], "serve") == 0) return serve();
    fprintf(stderr, "Usage: %s {serve|self-test}\n", base);
    return 2;
}
