import os
import pty
import fcntl
import pwd
import select
import signal
import subprocess
import sys
import termios
import time


def fail(message):
    raise SystemExit("session auth test failed: " + message)


def launch(driver, username, password, running):
    master, slave = pty.openpty()
    tty = os.ttyname(slave)
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            for fd in (0, 1, 2):
                os.dup2(slave, fd)
            if slave > 2:
                os.close(slave)
            os.close(master)
            child_env = os.environ.copy()
            child_env["VEYRA_SESSION_TEST_PASSWORD"] = password
            os.execve(driver, [driver, "login", username, tty], child_env)
        except Exception as error:
            os.write(2, ("test harness child: " + str(error) + "\n").encode())
            os._exit(127)

    os.close(slave)
    running.append((pid, master))
    output = bytearray()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        readable, _, _ = select.select([master], [], [], 0.25)
        if not readable:
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        output.extend(chunk)
        for line in output.splitlines():
            fields = line.split(b"\t")
            if len(fields) == 3 and fields[0] == b"READY":
                return pid, master, fields[1].decode("ascii")

    fail("PTY login process did not issue a grant: " + repr(bytes(output)))


def consume(binary, token, pid):
    return subprocess.run(
        [binary, "consume", token, str(pid)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )


def check_password(driver, username, password, expected):
    child_env = os.environ.copy()
    child_env["VEYRA_SESSION_TEST_PASSWORD"] = password
    result = subprocess.run(
        [driver, "auth", username],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_env,
        timeout=10,
    )
    if result.returncode != 0 or result.stdout.strip() != expected:
        fail("PAM system-password check mismatch: " + result.stderr.strip())


def stop_all(running):
    cleanup_failures = []
    for pid, master in running:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            waited, status = os.waitpid(pid, 0)
            if waited == pid and (
                not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0
            ):
                cleanup_failures.append((pid, status))
        except ChildProcessError:
            pass
        try:
            os.close(master)
        except OSError:
            pass
    if cleanup_failures:
        fail("PAM close-session cleanup failed: " + repr(cleanup_failures))


def main():
    if os.geteuid() != 0:
        fail("must run as root")
    if len(sys.argv) != 6:
        fail("usage: test-session-auth.py DRIVER CONSUMER MAPPING_FILE USERNAME PASSWORD_FILE")

    driver, consumer, mapping_file, username, password_file = sys.argv[1:]
    with open(password_file, encoding="ascii") as password_input:
        test_password = password_input.read().strip()
    if not test_password:
        fail("test password file is empty")
    running = []
    try:
        check_password(driver, username, "incorrect-password", "AUTH_REJECTED")
        check_password(driver, username, test_password, "AUTH_ACCEPTED")
        pid, _, token = launch(driver, username, test_password, running)

        wrong_pid = consume(consumer, token, os.getpid())
        if wrong_pid.returncode == 0:
            fail("grant accepted a different peer PID")

        accepted = consume(consumer, token, pid)
        account = pwd.getpwnam(username)
        expected_prefix = "authorized\t{}\t{}\t{}\t300000\t".format(
            username, account.pw_uid, account.pw_gid
        )
        if accepted.returncode != 0 or not accepted.stdout.startswith(expected_prefix):
            fail("valid grant was rejected: " + accepted.stderr.strip())

        replay = consume(consumer, token, pid)
        if replay.returncode == 0:
            fail("one-use grant was accepted twice")

        revoked_pid, _, revoked_token = launch(driver, username, test_password, running)
        with open(mapping_file, "w", encoding="ascii") as mapping:
            mapping.write("400000\n")
        revoked = consume(consumer, revoked_token, revoked_pid)
        if revoked.returncode == 0:
            fail("grant survived an account mapping change")
        os.unlink(mapping_file)

        expired_pid, _, expired_token = launch(driver, username, test_password, running)
        time.sleep(2)
        expired = consume(consumer, expired_token, expired_pid)
        if expired.returncode == 0:
            fail("expired grant was accepted")

        print("PAM rejects wrong passwords and session grants reject wrong PID, mapping changes, replay and expiry")
    finally:
        stop_all(running)


if __name__ == "__main__":
    main()
