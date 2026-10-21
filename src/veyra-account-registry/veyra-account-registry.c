#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <mntent.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REGISTRY_DIR "registry"
#define REGISTRY_FILE "accounts.v1"
#define LOCK_FILE ".accounts.lock"
#define MAX_RECORDS 10000U
#define MAX_FILE_SIZE (2U * 1024U * 1024U)
#define FIRST_UID_BASE UINT32_C(300000)
#define UID_SLOT_STEP UINT32_C(100000)
#define MAPPED_UID_COUNT UINT32_C(65536)
#define MAX_UID_BASE UINT32_C(4294900000)
#define MAX_ACCOUNT_NAME 32U

#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC 0xEF53
#endif

struct account_record {
    char name[MAX_ACCOUNT_NAME + 1U];
    uint32_t system_uid;
    uint32_t system_gid;
    uint32_t uid_base;
    bool retired;
};

struct registry {
    struct account_record *records;
    size_t count;
    size_t capacity;
    uint32_t next_uid_base;
};

static void report_errno(const char *message) {
    fprintf(stderr, "veyra-account-registry: %s: %s\n", message,
            strerror(errno));
}

static int fail(const char *message) {
    fprintf(stderr, "veyra-account-registry: %s\n", message);
    return 1;
}

static bool valid_account_name(const char *name) {
    size_t length = strlen(name);
    if (length == 0U || length > MAX_ACCOUNT_NAME) return false;
    if (!((name[0] >= 'a' && name[0] <= 'z') || name[0] == '_')) return false;
    for (size_t i = 1U; i < length; ++i) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-')) return false;
    }
    return true;
}

static bool parse_u32(const char *text, uint32_t *value) {
    if (text == NULL || *text == '\0') return false;
    if (text[0] == '+' || text[0] == '-') return false;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        parsed > UINT32_MAX) return false;
    char canonical[16];
    (void)snprintf(canonical, sizeof(canonical), "%llu", parsed);
    if (strcmp(canonical, text) != 0) return false;
    *value = (uint32_t)parsed;
    return true;
}

static bool safe_root_directory(int fd, const char *label, bool exact_mode) {
    struct stat st;
    if (fstat(fd, &st) < 0) {
        report_errno(label);
        return false;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 07022) != 0 ||
        (exact_mode && (st.st_mode & 0777) != 0700)) {
        fprintf(stderr, "veyra-account-registry: unsafe owner or mode on %s\n",
                label);
        return false;
    }
    return true;
}

#ifndef VEYRA_REGISTRY_TESTING
static int open_component(int parent, const char *name, const char *label) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        report_errno(label);
        return -1;
    }
    if (!safe_root_directory(fd, label, false)) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool exact_ext4_mount(const char *path) {
    FILE *mounts = setmntent("/proc/self/mounts", "r");
    if (mounts == NULL) {
        report_errno("open /proc/self/mounts");
        return false;
    }
    bool found = false;
    struct mntent *entry;
    while ((entry = getmntent(mounts)) != NULL) {
        if (strcmp(entry->mnt_dir, path) == 0 &&
            strcmp(entry->mnt_type, "ext4") == 0) {
            found = true;
            break;
        }
    }
    endmntent(mounts);
    return found;
}
#endif

static int open_store(void) {
#ifdef VEYRA_REGISTRY_TESTING
    const char *test_path = getenv("VEYRA_TEST_STORE");
    if (test_path == NULL || test_path[0] != '/') {
        (void)fail("test binary requires an absolute VEYRA_TEST_STORE path");
        return -1;
    }
    int fd = open(test_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        report_errno("open test store");
        return -1;
    }
    if (!safe_root_directory(fd, "test store", false)) {
        close(fd);
        return -1;
    }
    return fd;
#else
    int root_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) {
        report_errno("open root directory");
        return -1;
    }
    int var_fd = open_component(root_fd, "var", "/var");
    close(root_fd);
    if (var_fd < 0) return -1;
    int lib_fd = open_component(var_fd, "lib", "/var/lib");
    close(var_fd);
    if (lib_fd < 0) return -1;
    int store_fd = open_component(lib_fd, "veyra-user-store",
                                  "/var/lib/veyra-user-store");
    if (store_fd < 0) {
        close(lib_fd);
        return -1;
    }
    struct stat store_st;
    struct stat lib_st;
    struct statfs fs;
    bool valid = fstat(store_fd, &store_st) == 0 && fstat(lib_fd, &lib_st) == 0 &&
                 fstatfs(store_fd, &fs) == 0;
    if (!valid) {
        report_errno("inspect persistent store");
        close(store_fd);
        close(lib_fd);
        return -1;
    }
    if (store_st.st_dev == lib_st.st_dev || fs.f_type != EXT4_SUPER_MAGIC ||
        !exact_ext4_mount("/var/lib/veyra-user-store")) {
        (void)fail("user store must be its own mounted ext4 filesystem");
        close(store_fd);
        close(lib_fd);
        return -1;
    }
    close(lib_fd);
    return store_fd;
#endif
}

static int open_registry_directory(int store_fd) {
    bool created = false;
    if (mkdirat(store_fd, REGISTRY_DIR, 0700) == 0) {
        created = true;
    } else if (errno != EEXIST) {
        report_errno("create registry directory");
        return -1;
    }
    if (created && fsync(store_fd) < 0) {
        report_errno("sync persistent store after creating registry directory");
        return -1;
    }
    int fd = openat(store_fd, REGISTRY_DIR,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        report_errno("open registry directory");
        return -1;
    }
    if (!safe_root_directory(fd, "registry directory", true)) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool valid_base(uint32_t base) {
    return base >= FIRST_UID_BASE && base <= MAX_UID_BASE &&
           base % UID_SLOT_STEP == 0U &&
           (uint64_t)base + MAPPED_UID_COUNT - 1U <= UINT32_MAX;
}

static int append_record(struct registry *registry,
                         const struct account_record *record) {
    if (registry->count >= MAX_RECORDS) return fail("registry record limit reached");
    if (registry->count == registry->capacity) {
        size_t next = registry->capacity == 0U ? 16U : registry->capacity * 2U;
        if (next > MAX_RECORDS) next = MAX_RECORDS;
        struct account_record *grown = realloc(registry->records,
                                               next * sizeof(*grown));
        if (grown == NULL) {
            report_errno("allocate registry records");
            return 1;
        }
        registry->records = grown;
        registry->capacity = next;
    }
    registry->records[registry->count++] = *record;
    return 0;
}

static bool split_fields(char *line, char **fields, size_t expected) {
    size_t count = 0U;
    char *start = line;
    for (char *cursor = line;; ++cursor) {
        if (*cursor == '\t' || *cursor == '\0') {
            if (cursor == start || count >= expected) return false;
            fields[count++] = start;
            if (*cursor == '\0') break;
            *cursor = '\0';
            start = cursor + 1;
        }
    }
    return count == expected;
}

static int parse_registry_data(char *data, size_t length,
                               struct registry *registry) {
    if (length == 0U || data[length - 1U] != '\n')
        return fail("registry is truncated or lacks a final newline");
    if (memchr(data, '\0', length) != NULL)
        return fail("registry contains a NUL byte");
    data[length] = '\0';
    char *cursor = data;
    char *newline = strchr(cursor, '\n');
    if (newline == NULL) return fail("registry header is missing");
    *newline = '\0';
    char *header[3];
    if (!split_fields(cursor, header, 3U) ||
        strcmp(header[0], "VEYRA-USER-REGISTRY") != 0 ||
        strcmp(header[1], "1") != 0 ||
        !parse_u32(header[2], &registry->next_uid_base))
        return fail("registry header is invalid");

    cursor = newline + 1;
    uint32_t highest_base = 0U;
    while (*cursor != '\0') {
        newline = strchr(cursor, '\n');
        if (newline == NULL) return fail("registry record is truncated");
        *newline = '\0';
        if (strlen(cursor) > 160U) return fail("registry record is too long");
        char *fields[5];
        if (!split_fields(cursor, fields, 5U))
            return fail("registry record has invalid fields");
        struct account_record record = {0};
        if (strcmp(fields[0], "active") == 0) record.retired = false;
        else if (strcmp(fields[0], "retired") == 0) record.retired = true;
        else return fail("registry record has an invalid state");
        if (!valid_account_name(fields[1]) ||
            !parse_u32(fields[2], &record.system_uid) ||
            !parse_u32(fields[3], &record.system_gid) ||
            !parse_u32(fields[4], &record.uid_base) ||
            record.system_uid < 1000U || record.system_uid >= 60000U ||
            record.system_gid == 0U || record.system_gid >= 60000U ||
            !valid_base(record.uid_base))
            return fail("registry record contains an invalid identity or range");
        (void)snprintf(record.name, sizeof(record.name), "%s", fields[1]);
        for (size_t i = 0U; i < registry->count; ++i) {
            if (strcmp(registry->records[i].name, record.name) == 0 ||
                registry->records[i].uid_base == record.uid_base ||
                registry->records[i].system_uid == record.system_uid)
                return fail("registry contains a duplicate name or UID range");
        }
        if (append_record(registry, &record) != 0) return 1;
        if (record.uid_base > highest_base) highest_base = record.uid_base;
        cursor = newline + 1;
    }
    if (registry->next_uid_base == 0U) {
        if (highest_base != MAX_UID_BASE)
            return fail("registry exhaustion marker is inconsistent");
    } else if (!valid_base(registry->next_uid_base) ||
               registry->next_uid_base <= highest_base) {
        return fail("registry next-range marker is inconsistent");
    }
    return 0;
}

static int load_registry(int registry_fd, struct registry *registry) {
    memset(registry, 0, sizeof(*registry));
    registry->next_uid_base = FIRST_UID_BASE;
    int fd = openat(registry_fd, REGISTRY_FILE,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) return 0;
        report_errno("open registry file");
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        report_errno("inspect registry file");
        close(fd);
        return 1;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0777) != 0600 || st.st_size < 1 ||
        (uint64_t)st.st_size > MAX_FILE_SIZE) {
        close(fd);
        return fail("registry file has unsafe ownership, mode or size");
    }
    size_t length = (size_t)st.st_size;
    char *data = malloc(length + 1U);
    if (data == NULL) {
        report_errno("allocate registry input");
        close(fd);
        return 1;
    }
    size_t offset = 0U;
    while (offset < length) {
        ssize_t got = read(fd, data + offset, length - offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            if (got == 0) errno = EIO;
            report_errno("read registry file");
            free(data);
            close(fd);
            return 1;
        }
        offset += (size_t)got;
    }
    close(fd);
    int result = parse_registry_data(data, length, registry);
    free(data);
    return result;
}

static int write_all(int fd, const char *data, size_t length) {
    size_t offset = 0U;
    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            if (written == 0) errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int write_registry(int registry_fd, const struct registry *registry) {
    char temp_name[64];
    int temp_fd = -1;
    for (unsigned int attempt = 0U; attempt < 100U; ++attempt) {
        (void)snprintf(temp_name, sizeof(temp_name), ".accounts.v1.tmp.%ld.%u",
                       (long)getpid(), attempt);
        temp_fd = openat(registry_fd, temp_name,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                         0600);
        if (temp_fd >= 0 || errno != EEXIST) break;
    }
    if (temp_fd < 0) {
        report_errno("create temporary registry");
        return 1;
    }
    bool ready = fchmod(temp_fd, 0600) == 0 && fchown(temp_fd, 0, 0) == 0;
    char line[192];
    int n = snprintf(line, sizeof(line), "VEYRA-USER-REGISTRY\t1\t%u\n",
                     registry->next_uid_base);
    if (!ready) {
        report_errno("secure temporary registry");
        close(temp_fd);
        (void)unlinkat(registry_fd, temp_name, 0);
        return 1;
    }
    if (n < 0 || (size_t)n >= sizeof(line) ||
        write_all(temp_fd, line, (size_t)n) < 0) {
        report_errno("write registry header");
        close(temp_fd);
        (void)unlinkat(registry_fd, temp_name, 0);
        return 1;
    }
    for (size_t i = 0U; i < registry->count; ++i) {
        const struct account_record *record = &registry->records[i];
        n = snprintf(line, sizeof(line), "%s\t%s\t%u\t%u\t%u\n",
                     record->retired ? "retired" : "active", record->name,
                     record->system_uid, record->system_gid, record->uid_base);
        if (n < 0 || (size_t)n >= sizeof(line) ||
            write_all(temp_fd, line, (size_t)n) < 0) {
            report_errno("write registry record");
            close(temp_fd);
            (void)unlinkat(registry_fd, temp_name, 0);
            return 1;
        }
    }
    int sync_result = fsync(temp_fd);
    int sync_errno = errno;
    int close_result = close(temp_fd);
    if (sync_result < 0 || close_result < 0) {
        if (sync_result < 0) errno = sync_errno;
        report_errno("sync temporary registry");
        (void)unlinkat(registry_fd, temp_name, 0);
        return 1;
    }
    if (renameat(registry_fd, temp_name, registry_fd, REGISTRY_FILE) < 0) {
        report_errno("publish registry");
        (void)unlinkat(registry_fd, temp_name, 0);
        return 1;
    }
    if (fsync(registry_fd) < 0) {
        report_errno("sync registry directory after publish");
        return 1;
    }
    return 0;
}

static int open_lock(int registry_fd) {
    int fd = openat(registry_fd, LOCK_FILE,
                    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        report_errno("open registry lock");
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        report_errno("inspect registry lock");
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0777) != 0600) {
        (void)fail("registry lock has unsafe ownership or mode");
        close(fd);
        return -1;
    }
    while (flock(fd, LOCK_EX) < 0) {
        if (errno == EINTR) continue;
        report_errno("lock registry");
        close(fd);
        return -1;
    }
    return fd;
}

static bool account_has_forbidden_group(const struct passwd *pw) {
    const char *forbidden[] = {"wheel", "sudo"};
    for (size_t i = 0U; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
        struct group *group = getgrnam(forbidden[i]);
        if (group == NULL) continue;
        if (pw->pw_gid == group->gr_gid) return true;
        if (group->gr_mem != NULL) {
            for (char **member = group->gr_mem; *member != NULL; ++member) {
                if (strcmp(*member, pw->pw_name) == 0) return true;
            }
        }
    }
    int count = 16;
    gid_t *groups = malloc((size_t)count * sizeof(*groups));
    if (groups == NULL) return true;
    int rc = getgrouplist(pw->pw_name, pw->pw_gid, groups, &count);
    if (rc < 0) {
        if (count <= 0 || count > 4096) {
            free(groups);
            return true;
        }
        gid_t *grown = realloc(groups, (size_t)count * sizeof(*groups));
        if (grown == NULL) {
            free(groups);
            return true;
        }
        groups = grown;
        rc = getgrouplist(pw->pw_name, pw->pw_gid, groups, &count);
    }
    if (rc < 0) {
        free(groups);
        return true;
    }
    for (int i = 0; i < count; ++i) {
        struct group *group = getgrgid(groups[i]);
        if (group == NULL) continue;
        for (size_t j = 0U; j < sizeof(forbidden) / sizeof(forbidden[0]); ++j) {
            if (strcmp(group->gr_name, forbidden[j]) == 0) {
                free(groups);
                return true;
            }
        }
    }
    free(groups);
    return false;
}

static bool sudo_policy_is_clear(const char *name) {
    const char *sudo_path = NULL;
    struct stat st;
    const char *candidates[] = {"/usr/bin/sudo", "/bin/sudo"};
    for (size_t i = 0U; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        if (stat(candidates[i], &st) == 0) {
            sudo_path = candidates[i];
            break;
        }
        if (errno != ENOENT) {
            report_errno("inspect host sudo executable");
            return false;
        }
    }
    if (sudo_path == NULL) return true;
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) != 0 ||
        access(sudo_path, X_OK) < 0) {
        (void)fail("host sudo executable has unsafe ownership, mode or access");
        return false;
    }
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) < 0) {
        report_errno("create host sudo policy pipe");
        return false;
    }
    pid_t child = fork();
    if (child < 0) {
        report_errno("start host sudo policy query");
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return false;
    }
    if (child == 0) {
        close(pipe_fds[0]);
        if (dup2(pipe_fds[1], STDOUT_FILENO) < 0 ||
            dup2(pipe_fds[1], STDERR_FILENO) < 0) _exit(126);
        close(pipe_fds[1]);
        char *const arguments[] = {"sudo", "-n", "-l", "-U", (char *)name, NULL};
        char *const environment[] = {"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL};
        execve(sudo_path, arguments, environment);
        _exit(127);
    }
    close(pipe_fds[1]);
    char output[8192];
    size_t used = 0U;
    bool overflow = false;
    bool timed_out = false;
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) < 0) {
        report_errno("start sudo policy timeout");
        (void)kill(child, SIGKILL);
        close(pipe_fds[0]);
        (void)waitpid(child, NULL, 0);
        return false;
    }
    deadline.tv_sec += 5;
    for (;;) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
            report_errno("check sudo policy timeout");
            (void)kill(child, SIGKILL);
            close(pipe_fds[0]);
            (void)waitpid(child, NULL, 0);
            return false;
        }
        long remaining_ms = (deadline.tv_sec - now.tv_sec) * 1000L +
                            (deadline.tv_nsec - now.tv_nsec) / 1000000L;
        if (remaining_ms <= 0) {
            timed_out = true;
            break;
        }
        struct pollfd poll_fd = {.fd = pipe_fds[0], .events = POLLIN | POLLHUP};
        int ready = poll(&poll_fd, 1U,
                         remaining_ms > INT32_MAX ? INT32_MAX : (int)remaining_ms);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            report_errno("read host sudo policy result");
            (void)kill(child, SIGKILL);
            close(pipe_fds[0]);
            (void)waitpid(child, NULL, 0);
            return false;
        }
        if (ready == 0) {
            timed_out = true;
            break;
        }
        char chunk[1024];
        ssize_t got = read(pipe_fds[0], chunk, sizeof(chunk));
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) {
            report_errno("read host sudo policy output");
            (void)kill(child, SIGKILL);
            close(pipe_fds[0]);
            (void)waitpid(child, NULL, 0);
            return false;
        }
        if (got == 0) break;
        size_t amount = (size_t)got;
        if (amount > sizeof(output) - 1U - used) {
            overflow = true;
            break;
        }
        memcpy(output + used, chunk, amount);
        used += amount;
    }
    close(pipe_fds[0]);
    if (timed_out || overflow) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
        (void)fail(timed_out ? "host sudo policy query timed out" :
                              "host sudo policy output exceeded its limit");
        return false;
    }
    output[used] = '\0';
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        report_errno("wait for host sudo policy query");
        return false;
    }
    if (strstr(output, "is not allowed to run sudo") != NULL) return true;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        (void)fail("host sudo policy grants this account a sudo authorization");
        return false;
    }
    (void)fail("cannot prove that host sudo denies this account");
    return false;
}

static const struct passwd *lookup_eligible_account(const char *name) {
    struct passwd *pw = getpwnam(name);
    if (pw == NULL) {
        (void)fail("system account does not exist");
        return NULL;
    }
    if (pw->pw_uid < 1000U || pw->pw_uid >= 60000U ||
        pw->pw_gid == 0U || pw->pw_gid >= 60000U) {
        (void)fail("system UID or GID is outside the normal-account range");
        return NULL;
    }
    if (pw->pw_shell == NULL ||
        (strcmp(pw->pw_shell, "/sbin/nologin") != 0 &&
         strcmp(pw->pw_shell, "/usr/sbin/nologin") != 0 &&
         strcmp(pw->pw_shell, "/bin/false") != 0)) {
        (void)fail("system account must have a locked non-shell login path");
        return NULL;
    }
    struct spwd *shadow = getspnam(name);
    if (shadow == NULL || shadow->sp_pwdp == NULL || shadow->sp_pwdp[0] == '\0' ||
        shadow->sp_pwdp[0] == '!' || shadow->sp_pwdp[0] == '*') {
        (void)fail("system account must have an active system-authenticator password");
        return NULL;
    }
    time_t now = time(NULL);
    if (now < 0) {
        (void)fail("cannot determine whether the system account is expired");
        return NULL;
    }
    long today = (long)(now / 86400);
    if (shadow->sp_expire >= 0 && today > shadow->sp_expire) {
        (void)fail("system account has expired");
        return NULL;
    }
    if (shadow->sp_lstchg == 0 ||
        (shadow->sp_lstchg >= 0 && shadow->sp_max >= 0 &&
         today > shadow->sp_lstchg &&
         today - shadow->sp_lstchg > shadow->sp_max)) {
        (void)fail("system account password has expired or must be changed");
        return NULL;
    }
    if (account_has_forbidden_group(pw)) {
        (void)fail("system account belongs to host wheel or sudo");
        return NULL;
    }
    if (!sudo_policy_is_clear(name)) return NULL;
    return pw;
}

static struct account_record *find_record(struct registry *registry,
                                          const char *name) {
    for (size_t i = 0U; i < registry->count; ++i) {
        if (strcmp(registry->records[i].name, name) == 0)
            return &registry->records[i];
    }
    return NULL;
}

static int print_registry(const struct registry *registry) {
    for (size_t i = 0U; i < registry->count; ++i) {
        const struct account_record *record = &registry->records[i];
        printf("%s\t%s\t%u:%u\t%u\n", record->name,
               record->retired ? "retired" : "active", record->system_uid,
               record->system_gid, record->uid_base);
    }
    return ferror(stdout) ? fail("could not write registry listing") : 0;
}

static int resolve_account(struct registry *registry, const char *name) {
    struct account_record *record = find_record(registry, name);
    if (record == NULL) return fail("account is not enrolled");
    if (record->retired) return fail("account enrollment is retired");
    const struct passwd *pw = lookup_eligible_account(name);
    if (pw == NULL) return 1;
    if (record->system_uid != (uint32_t)pw->pw_uid ||
        record->system_gid != (uint32_t)pw->pw_gid)
        return fail("system account identity changed after enrollment");
    printf("resolved\t%s\t%u\t%u\t%u\n", record->name,
           record->system_uid, record->system_gid, record->uid_base);
    return ferror(stdout) ? fail("could not write account mapping") : 0;
}

static void usage(FILE *stream) {
    fprintf(stream,
            "Usage: veyra-account-registry {enroll USER|retire USER|resolve USER|list}\n");
}

int main(int argc, char **argv) {
    if (geteuid() != 0) return fail("must be run by system root");
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }
    if (argc < 2 || argc > 3 ||
        (strcmp(argv[1], "list") != 0 && argc != 3) ||
        (strcmp(argv[1], "list") == 0 && argc != 2)) {
        usage(stderr);
        return 2;
    }
    if (strcmp(argv[1], "list") != 0 &&
        strcmp(argv[1], "enroll") != 0 && strcmp(argv[1], "retire") != 0 &&
        strcmp(argv[1], "resolve") != 0) {
        usage(stderr);
        return 2;
    }
    if (strcmp(argv[1], "list") != 0 && !valid_account_name(argv[2]))
        return fail("account name is invalid");

    int store_fd = open_store();
    if (store_fd < 0) return 1;
    int registry_fd = open_registry_directory(store_fd);
    close(store_fd);
    if (registry_fd < 0) return 1;
    int lock_fd = open_lock(registry_fd);
    if (lock_fd < 0) {
        close(registry_fd);
        return 1;
    }

    struct registry registry;
    if (load_registry(registry_fd, &registry) != 0) {
        close(lock_fd);
        close(registry_fd);
        free(registry.records);
        return 1;
    }
    int result = 0;
    if (strcmp(argv[1], "list") == 0) {
        result = print_registry(&registry);
    } else if (strcmp(argv[1], "resolve") == 0) {
        result = resolve_account(&registry, argv[2]);
    } else if (strcmp(argv[1], "enroll") == 0) {
        const struct passwd *pw = lookup_eligible_account(argv[2]);
        if (pw == NULL) {
            result = 1;
        } else {
            struct account_record *existing = find_record(&registry, argv[2]);
            if (existing != NULL) {
                if (existing->retired) result = fail("retired account names cannot be reused");
                else if (existing->system_uid != (uint32_t)pw->pw_uid ||
                         existing->system_gid != (uint32_t)pw->pw_gid)
                    result = fail("system account identity changed after enrollment");
                else printf("already-enrolled\t%s\t%u\n", existing->name,
                            existing->uid_base);
            } else if (registry.next_uid_base == 0U) {
                result = fail("all mapped UID/GID ranges are reserved");
            } else {
                struct account_record record = {0};
                (void)snprintf(record.name, sizeof(record.name), "%s", argv[2]);
                record.system_uid = (uint32_t)pw->pw_uid;
                record.system_gid = (uint32_t)pw->pw_gid;
                record.uid_base = registry.next_uid_base;
                uint64_t next = (uint64_t)record.uid_base + UID_SLOT_STEP;
                registry.next_uid_base = next > MAX_UID_BASE ? 0U : (uint32_t)next;
                if (!valid_base(record.uid_base) || append_record(&registry, &record) != 0) {
                    result = fail("could not reserve mapped UID/GID range");
                } else if (write_registry(registry_fd, &registry) != 0) {
                    result = 1;
                } else {
                    printf("enrolled\t%s\t%u:%u\t%u\n", record.name,
                           record.system_uid, record.system_gid, record.uid_base);
                }
            }
        }
    } else if (strcmp(argv[1], "retire") == 0) {
        struct account_record *record = find_record(&registry, argv[2]);
        if (record == NULL) {
            result = fail("account is not enrolled");
        } else if (!record->retired) {
            record->retired = true;
            result = write_registry(registry_fd, &registry);
            if (result == 0) printf("retired\t%s\t%u\n", record->name,
                                    record->uid_base);
        } else {
            printf("already-retired\t%s\t%u\n", record->name, record->uid_base);
        }
    } else {
        usage(stderr);
        result = 2;
    }
    free(registry.records);
    close(lock_fd);
    close(registry_fd);
    return result;
}
