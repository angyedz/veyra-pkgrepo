#define _GNU_SOURCE
#include <security/pam_appl.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define BRIDGE_PAM_SERVICE "veyra-root-bridge"
#define TRUSTED_TTY "/dev/tty9"
#define POLICY_DIR "/var/log/veyra"
#define AUDIT_FILE "root-bridge.log"
#if defined(VEYRA_ROOT_BRIDGE_TEST_IDLE_TIMEOUT_SECONDS)
#define IDLE_TIMEOUT_SECONDS VEYRA_ROOT_BRIDGE_TEST_IDLE_TIMEOUT_SECONDS
#else
#define IDLE_TIMEOUT_SECONDS 900
#endif
#define MAX_USERNAME 64U
#define MAX_SECRET 1024U
#define INPUT_BUFFER_SIZE 4096U
#define WRITE_LITERAL(fd, literal) \
    write_all((fd), (literal), sizeof(literal) - 1U)

static const char *trusted_tty_path(void) {
#ifdef VEYRA_ROOT_BRIDGE_TEST_TTY
    const char *test_tty = getenv("VEYRA_ROOT_BRIDGE_TEST_TTY");
    if (test_tty != NULL && test_tty[0] == '/')
        return test_tty;
#endif
    return TRUSTED_TTY;
}

static const char *audit_directory_path(void) {
#ifdef VEYRA_ROOT_BRIDGE_TEST_AUDIT_DIR
    const char *test_directory = getenv("VEYRA_ROOT_BRIDGE_TEST_AUDIT_DIR");
    if (test_directory != NULL && test_directory[0] == '/')
        return test_directory;
#endif
    return POLICY_DIR;
}

static volatile sig_atomic_t caught_signal;
static volatile sig_atomic_t resize_requested;
static struct termios saved_tty;
static bool tty_state_saved;

static void forward_signal(int signal_number);

static void wipe_memory(void *memory, size_t length) {
    volatile unsigned char *cursor = memory;
    while (length-- > 0U)
        *cursor++ = 0;
}

static int write_all(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    while (length > 0U) {
        const ssize_t amount = write(fd, cursor, length);
        if (amount < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (amount == 0) {
            errno = EIO;
            return -1;
        }
        cursor += (size_t)amount;
        length -= (size_t)amount;
    }
    return 0;
}

static int valid_username(const char *name) {
    const size_t length = strlen(name);
    if (length == 0U || length > MAX_USERNAME ||
        !((name[0] >= 'a' && name[0] <= 'z') ||
          (name[0] >= 'A' && name[0] <= 'Z') || name[0] == '_'))
        return 0;
    for (size_t i = 1U; i < length; i++) {
        const char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int read_line(int fd, char *buffer, size_t capacity, bool secret) {
    if (capacity < 2U) {
        errno = EINVAL;
        return -1;
    }
    struct termios original;
    bool restore = false;
    if (secret) {
        if (tcgetattr(fd, &original) < 0)
            return -1;
        struct termios hidden = original;
        hidden.c_lflag &= (tcflag_t)~(ECHO | ECHONL);
        if (tcsetattr(fd, TCSAFLUSH, &hidden) < 0)
            return -1;
        restore = true;
    }

    size_t used = 0U;
    bool overflow = false;
    for (;;) {
        unsigned char byte;
        const ssize_t amount = read(fd, &byte, 1U);
        if (amount < 0) {
            if (errno == EINTR && caught_signal == 0)
                continue;
            if (restore)
                (void)tcsetattr(fd, TCSAFLUSH, &original);
            wipe_memory(buffer, capacity);
            return -1;
        }
        if (amount == 0) {
            if (restore)
                (void)tcsetattr(fd, TCSAFLUSH, &original);
            wipe_memory(buffer, capacity);
            errno = EIO;
            return -1;
        }
        if (byte == '\n' || byte == '\r')
            break;
        if (byte == '\0') {
            overflow = true;
            continue;
        }
        if (used + 1U < capacity)
            buffer[used++] = (char)byte;
        else
            overflow = true;
    }

    if (restore) {
        (void)tcsetattr(fd, TCSAFLUSH, &original);
        (void)write_all(fd, "\n", 1U);
    }
    if (overflow) {
        wipe_memory(buffer, capacity);
        errno = EOVERFLOW;
        return -1;
    }
    buffer[used] = '\0';
    return 0;
}

static int pam_conversation(int count, const struct pam_message **messages,
                            struct pam_response **responses, void *data) {
    if (count <= 0 || messages == NULL || responses == NULL || data == NULL)
        return PAM_CONV_ERR;
    const int tty_fd = *(const int *)data;
    struct pam_response *answer = calloc((size_t)count, sizeof(*answer));
    if (answer == NULL)
        return PAM_BUF_ERR;

    for (int i = 0; i < count; i++) {
        if (messages[i] == NULL || messages[i]->msg == NULL)
            goto failed;
        switch (messages[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
        case PAM_PROMPT_ECHO_ON: {
            const size_t capacity = messages[i]->msg_style == PAM_PROMPT_ECHO_OFF
                                        ? MAX_SECRET
                                        : MAX_USERNAME + 1U;
            answer[i].resp = calloc(capacity, 1U);
            if (answer[i].resp == NULL ||
                write_all(tty_fd, messages[i]->msg,
                          strlen(messages[i]->msg)) < 0 ||
                read_line(tty_fd, answer[i].resp, capacity,
                          messages[i]->msg_style == PAM_PROMPT_ECHO_OFF) < 0)
                goto failed;
            answer[i].resp_retcode = 0;
            break;
        }
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            if (write_all(tty_fd, messages[i]->msg,
                          strlen(messages[i]->msg)) < 0 ||
                write_all(tty_fd, "\n", 1U) < 0)
                goto failed;
            break;
        default:
            goto failed;
        }
    }
    *responses = answer;
    return PAM_SUCCESS;

failed:
    for (int i = 0; i < count; i++) {
        if (answer[i].resp != NULL) {
            wipe_memory(answer[i].resp, strlen(answer[i].resp));
            free(answer[i].resp);
        }
    }
    free(answer);
    return PAM_CONV_ERR;
}

static int trusted_console(void) {
    if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0)
        return 0;
    char tty_name[128];
    if (ttyname_r(STDIN_FILENO, tty_name, sizeof(tty_name)) != 0 ||
        strcmp(tty_name, trusted_tty_path()) != 0 || !isatty(STDIN_FILENO) ||
        !isatty(STDOUT_FILENO) || !isatty(STDERR_FILENO))
        return 0;
    struct stat input_stat;
    struct stat output_stat;
    struct stat error_stat;
    if (fstat(STDIN_FILENO, &input_stat) < 0 ||
        fstat(STDOUT_FILENO, &output_stat) < 0 ||
        fstat(STDERR_FILENO, &error_stat) < 0 ||
        !S_ISCHR(input_stat.st_mode) || !S_ISCHR(output_stat.st_mode) ||
        !S_ISCHR(error_stat.st_mode) ||
        input_stat.st_rdev != output_stat.st_rdev ||
        input_stat.st_rdev != error_stat.st_rdev)
        return 0;
    const pid_t terminal_session = tcgetsid(STDIN_FILENO);
    if (terminal_session < 0 || terminal_session != getsid(0))
        return 0;

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
        close(fd);
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

static int trusted_log_directory(int *directory_fd) {
    const int fd = open(audit_directory_path(),
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
        st.st_gid != 0 || (st.st_mode & 0022) != 0) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    *directory_fd = fd;
    return 0;
}

static int audit_event(const char *outcome, const char *username) {
    char record[256];
    const time_t now = time(NULL);
    struct tm timestamp;
    char formatted[32] = "unknown-time";
    if (now != (time_t)-1 && localtime_r(&now, &timestamp) != NULL)
        (void)strftime(formatted, sizeof(formatted), "%Y-%m-%dT%H:%M:%S%z",
                       &timestamp);
    const int length = snprintf(record, sizeof(record),
                                "%s outcome=%s user=%s tty=%s\n",
                                formatted, outcome, username,
                                trusted_tty_path());
    openlog("veyra-root-bridge", LOG_PID, LOG_AUTHPRIV);
    syslog(strcmp(outcome, "success") == 0 ? LOG_NOTICE : LOG_WARNING,
           "trusted console %s for account %s", outcome, username);
    if (length < 0 || (size_t)length >= sizeof(record))
        return -1;

    int directory_fd = -1;
    if (trusted_log_directory(&directory_fd) < 0)
        return -1;
    const int fd = openat(directory_fd, AUDIT_FILE,
                          O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    close(directory_fd);
    if (fd < 0)
        return -1;
    struct stat st;
    int result = -1;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 &&
        st.st_gid == 0 && st.st_nlink == 1 && (st.st_mode & 0777) == 0600) {
        if (write_all(fd, record, (size_t)length) == 0 && fsync(fd) == 0)
            result = 0;
    }
    close(fd);
    return result;
}

static void failed_attempt_delay(void) {
    const struct timespec delay = { .tv_sec = 2, .tv_nsec = 0 };
    struct timespec remaining = delay;
    while (nanosleep(&remaining, &remaining) < 0 && errno == EINTR &&
           caught_signal == 0)
        ;
}

static int monotonic_seconds(int64_t *seconds) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return -1;
    *seconds = (int64_t)now.tv_sec;
    return 0;
}

static void forward_signal(int signal_number) {
    if (signal_number == SIGWINCH)
        resize_requested = 1;
    else
        caught_signal = signal_number;
}

static int install_login_signal_handlers(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = forward_signal;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGINT, &action, NULL) == 0 &&
                   sigaction(SIGQUIT, &action, NULL) == 0 &&
                   sigaction(SIGHUP, &action, NULL) == 0 &&
                   sigaction(SIGTERM, &action, NULL) == 0
               ? 0
               : -1;
}

static void restore_tty(void) {
    if (tty_state_saved) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_tty);
        tty_state_saved = false;
    }
}

static void signal_shell_session(int master, pid_t shell, int signal_number) {
    pid_t foreground = -1;
    if (ioctl(master, TIOCGPGRP, &foreground) == 0 && foreground > 1)
        (void)kill(-foreground, signal_number);
    (void)kill(-shell, signal_number);
    (void)kill(shell, signal_number);
}

static void close_inherited_fds(void) {
    long limit = sysconf(_SC_OPEN_MAX);
    if (limit < 0 || limit > 65536)
        limit = 65536;
    for (int fd = STDERR_FILENO + 1; fd < limit; fd++)
        (void)close(fd);
}

static int open_pty_pair(int *master, int *slave,
                         const struct winsize *window) {
    const int master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master_fd < 0)
        return -1;
    if (grantpt(master_fd) < 0 || unlockpt(master_fd) < 0) {
        close(master_fd);
        return -1;
    }
    char slave_path[128];
    const int name_status = ptsname_r(master_fd, slave_path, sizeof(slave_path));
    if (name_status != 0) {
        close(master_fd);
        errno = name_status;
        return -1;
    }
    const int slave_fd = open(slave_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave_fd < 0) {
        close(master_fd);
        return -1;
    }
    if (ioctl(slave_fd, TIOCSWINSZ, window) < 0) {
        close(slave_fd);
        close(master_fd);
        return -1;
    }
    *master = master_fd;
    *slave = slave_fd;
    return 0;
}

static int launch_root_shell(void) {
    int64_t initial_activity = 0;
    if (monotonic_seconds(&initial_activity) < 0)
        return -1;
    int master = -1;
    int slave = -1;
    struct winsize window = { .ws_row = 24, .ws_col = 80 };
    (void)ioctl(STDIN_FILENO, TIOCGWINSZ, &window);
    if (window.ws_row == 0)
        window.ws_row = 24;
    if (window.ws_col == 0)
        window.ws_col = 80;
    if (open_pty_pair(&master, &slave, &window) < 0)
        return -1;
    const int flags = fcntl(master, F_GETFL);
    if (flags < 0 || fcntl(master, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(master);
        close(slave);
        return -1;
    }

    pid_t child = fork();
    if (child < 0) {
        close(master);
        close(slave);
        return -1;
    }
    if (child == 0) {
        close(master);
        if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) < 0)
            _exit(126);
        for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
            if (dup2(slave, fd) < 0)
                _exit(126);
        }
        if (slave > STDERR_FILENO)
            close(slave);
        close_inherited_fds();
        if (setgroups(0, NULL) < 0 || setgid(0) < 0 || setuid(0) < 0 ||
            chdir("/root") < 0)
            _exit(126);
        (void)umask(077);
        if (clearenv() != 0)
            _exit(126);
        char *const arguments[] = { (char *)"sh", NULL };
        char *const environment[] = {
            (char *)"HOME=/root",
            (char *)"USER=root",
            (char *)"LOGNAME=root",
            (char *)"SHELL=/bin/sh",
            (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            (char *)"TERM=linux",
            NULL,
        };
        execve("/bin/sh", arguments, environment);
        _exit(127);
    }
    close(slave);

    if (tcgetattr(STDIN_FILENO, &saved_tty) < 0) {
        (void)kill(-child, SIGKILL);
        (void)kill(child, SIGKILL);
        close(master);
        (void)waitpid(child, NULL, 0);
        return -1;
    }
    tty_state_saved = true;
    struct termios raw = saved_tty;
    raw.c_lflag &= (tcflag_t)~(ICANON | ECHO | ECHONL);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0) {
        (void)kill(-child, SIGKILL);
        (void)kill(child, SIGKILL);
        close(master);
        (void)waitpid(child, NULL, 0);
        restore_tty();
        return -1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = forward_signal;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGQUIT, &action, NULL);
    (void)sigaction(SIGHUP, &action, NULL);
    (void)sigaction(SIGTERM, &action, NULL);
    (void)sigaction(SIGWINCH, &action, NULL);

    unsigned char pending_input[INPUT_BUFFER_SIZE];
    size_t pending_length = 0U;
    bool pty_eof = false;
    bool child_exited = false;
    bool terminating = false;
    bool idle_expired = false;
    int child_status = 0;
    int64_t last_activity = initial_activity;
    int64_t terminate_at = 0;

    while (!pty_eof || !child_exited) {
        int64_t now = 0;
        if (monotonic_seconds(&now) < 0)
            now = last_activity + IDLE_TIMEOUT_SECONDS;
        if (resize_requested != 0) {
            resize_requested = 0;
            struct winsize resized;
            if (ioctl(STDIN_FILENO, TIOCGWINSZ, &resized) == 0)
                (void)ioctl(master, TIOCSWINSZ, &resized);
        }
        if (!child_exited && !terminating &&
            now - last_activity >= IDLE_TIMEOUT_SECONDS) {
            idle_expired = true;
            terminating = true;
            terminate_at = now + 5;
            (void)write_all(STDOUT_FILENO,
                            "\r\nSystem root session expired after inactivity.\r\n",
                            sizeof("\r\nSystem root session expired after inactivity.\r\n") - 1U);
            signal_shell_session(master, child, SIGTERM);
        }
        if (caught_signal != 0 && !terminating) {
            terminating = true;
            terminate_at = now + 5;
            signal_shell_session(master, child, caught_signal);
        }
        if (terminating && now >= terminate_at) {
            signal_shell_session(master, child, SIGKILL);
        }

        pid_t waited = waitpid(child, &child_status, WNOHANG);
        if (waited == child) {
            child_exited = true;
            if (!terminating) {
                terminating = true;
                terminate_at = now + 5;
                signal_shell_session(master, child, SIGHUP);
            }
        } else if (waited < 0 && errno != EINTR) {
            child_exited = true;
            child_status = 127 << 8;
            if (!terminating) {
                terminating = true;
                terminate_at = now + 5;
                signal_shell_session(master, child, SIGHUP);
            }
        }
        if (child_exited && pty_eof)
            break;

        struct pollfd descriptors[2];
        descriptors[0].fd = STDIN_FILENO;
        descriptors[0].events = !child_exited &&
                                        pending_length < sizeof(pending_input)
                                    ? POLLIN
                                    : 0;
        descriptors[0].revents = 0;
        descriptors[1].fd = master;
        descriptors[1].events = (pty_eof ? 0 : POLLIN) |
                                (pending_length > 0U ? POLLOUT : 0);
        descriptors[1].revents = 0;
        const int poll_result = poll(descriptors, 2, 250);
        if (poll_result < 0 && errno != EINTR)
            break;
        if ((descriptors[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            const ssize_t amount = read(STDIN_FILENO,
                                        pending_input + pending_length,
                                        sizeof(pending_input) - pending_length);
            if (amount > 0) {
                pending_length += (size_t)amount;
                (void)monotonic_seconds(&last_activity);
            } else if (amount == 0) {
                if (!terminating) {
                    terminating = true;
                    (void)monotonic_seconds(&terminate_at);
                    terminate_at += 5;
                    signal_shell_session(master, child, SIGHUP);
                }
            } else if (errno != EINTR && errno != EAGAIN) {
                if (!terminating) {
                    terminating = true;
                    (void)monotonic_seconds(&terminate_at);
                    terminate_at += 5;
                    signal_shell_session(master, child, SIGHUP);
                }
            }
        }
        if ((descriptors[1].revents & POLLOUT) != 0 && pending_length > 0U) {
            const ssize_t amount = write(master, pending_input, pending_length);
            if (amount > 0) {
                pending_length -= (size_t)amount;
                memmove(pending_input, pending_input + amount, pending_length);
            } else if (amount < 0 && errno != EINTR && errno != EAGAIN) {
                pty_eof = true;
            }
        }
        if ((descriptors[1].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            unsigned char output[4096];
            const ssize_t amount = read(master, output, sizeof(output));
            if (amount > 0) {
                if (write_all(STDOUT_FILENO, output, (size_t)amount) < 0)
                    pty_eof = true;
            } else if (amount == 0 || (amount < 0 && errno == EIO)) {
                pty_eof = true;
            } else if (amount < 0 && errno != EINTR && errno != EAGAIN) {
                pty_eof = true;
            }
        }
        if ((descriptors[1].revents & POLLNVAL) != 0)
            pty_eof = true;
    }

    if (!child_exited) {
        signal_shell_session(master, child, SIGHUP);
        const int64_t deadline = terminate_at;
        for (;;) {
            const pid_t waited = waitpid(child, &child_status, WNOHANG);
            if (waited == child || (waited < 0 && errno == ECHILD))
                break;
            int64_t now = 0;
            if (monotonic_seconds(&now) < 0 || now >= deadline) {
                signal_shell_session(master, child, SIGKILL);
            }
            (void)usleep(10000U);
        }
    }
    close(master);
    restore_tty();
    if (idle_expired)
        return 124;
    if (WIFEXITED(child_status))
        return WEXITSTATUS(child_status);
    if (WIFSIGNALED(child_status))
        return 128 + WTERMSIG(child_status);
    return 1;
}

int main(int argc, char **argv) {
    if ((argc > 1 && !(argc == 2 && strcmp(argv[1], "--") == 0)) ||
        !trusted_console()) {
        (void)WRITE_LITERAL(STDERR_FILENO,
                            "System root access is available only from the trusted system console.\n");
        return 1;
    }
    if (install_login_signal_handlers() < 0)
        return 1;
    close_inherited_fds();
    (void)WRITE_LITERAL(STDOUT_FILENO, "System administrator account: ");
    char username[MAX_USERNAME + 1U];
    if (read_line(STDIN_FILENO, username, sizeof(username), false) < 0 ||
        !valid_username(username)) {
        audit_event("failed", "invalid-account");
        failed_attempt_delay();
        (void)WRITE_LITERAL(STDOUT_FILENO, "Access denied.\n");
        return 1;
    }

    const int tty_fd = STDIN_FILENO;
    struct pam_conv conversation = {
        .conv = pam_conversation,
        .appdata_ptr = (void *)&tty_fd,
    };
    pam_handle_t *pamh = NULL;
    int status = pam_start(BRIDGE_PAM_SERVICE, username, &conversation, &pamh);
    if (status == PAM_SUCCESS)
        (void)pam_fail_delay(pamh, 2000000U);
    if (status == PAM_SUCCESS)
        status = pam_set_item(pamh, PAM_TTY, trusted_tty_path());
    if (status == PAM_SUCCESS)
        status = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
    if (status == PAM_SUCCESS)
        status = pam_acct_mgmt(pamh, 0);
    if (status != PAM_SUCCESS) {
        audit_event("failed", username);
        failed_attempt_delay();
        (void)WRITE_LITERAL(STDOUT_FILENO, "Access denied.\n");
        if (pamh != NULL)
            (void)pam_end(pamh, status);
        return 1;
    }

    status = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (status == PAM_SUCCESS)
        status = pam_open_session(pamh, 0);
    if (status != PAM_SUCCESS) {
        audit_event("failed", username);
        (void)WRITE_LITERAL(STDOUT_FILENO, "Unable to start system session.\n");
        (void)pam_setcred(pamh, PAM_DELETE_CRED);
        (void)pam_end(pamh, status);
        return 1;
    }

    if (audit_event("success", username) < 0) {
        (void)WRITE_LITERAL(STDOUT_FILENO,
                            "System audit is unavailable; access denied.\n");
        (void)pam_close_session(pamh, 0);
        (void)pam_setcred(pamh, PAM_DELETE_CRED);
        (void)pam_end(pamh, PAM_SESSION_ERR);
        wipe_memory(username, sizeof(username));
        return 1;
    }
    (void)WRITE_LITERAL(STDOUT_FILENO,
                        "Authenticated. Entering the system root shell.\r\n");
    const int shell_status = launch_root_shell();
    if (shell_status < 0) {
        audit_event("session-start-failed", username);
        (void)WRITE_LITERAL(STDOUT_FILENO, "Unable to start system shell.\r\n");
    } else {
        audit_event(shell_status == 124 ? "idle-timeout" : "session-ended",
                    username);
    }
    const int close_status = pam_close_session(pamh, 0);
    const int credential_status = pam_setcred(pamh, PAM_DELETE_CRED);
    const int end_status = pam_end(pamh, PAM_SUCCESS);
    if (close_status != PAM_SUCCESS || credential_status != PAM_SUCCESS ||
        end_status != PAM_SUCCESS)
        audit_event("cleanup-failed", username);
    wipe_memory(username, sizeof(username));
    closelog();
    return shell_status < 0 ? 1 : 0;
}
