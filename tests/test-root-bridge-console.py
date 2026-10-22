#!/usr/bin/env python3
import fcntl
import os
import pty
import select
import signal
import sys
import termios
import time


def fail(message):
    raise SystemExit("root bridge console test failed: " + message)


def start_console(binary, audit_dir):
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
            environment = {
                "PATH": "/attacker-controlled-path",
                "HOME": "/attacker-controlled-home",
                "TERM": "attacker-terminal",
                "DBUS_SESSION_BUS_ADDRESS": "unix:path=/attacker/socket",
                "VEYRA_ROOT_BRIDGE_TEST_TTY": tty,
                "VEYRA_ROOT_BRIDGE_TEST_AUDIT_DIR": audit_dir,
            }
            os.execve(binary, [binary, "--"], environment)
        except Exception as error:
            os.write(2, ("test harness child: " + str(error) + "\n").encode())
            os._exit(127)
    os.close(slave)
    return pid, master, tty


def read_until(master, output, marker, timeout=12):
    deadline = time.monotonic() + timeout
    while marker not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("timed out waiting for " + repr(marker) + ": " + repr(bytes(output)))
        readable, _, _ = select.select([master], [], [], min(remaining, 0.25))
        if not readable:
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        output.extend(chunk)
    if marker not in output:
        fail("console exited before " + repr(marker) + ": " + repr(bytes(output)))
    return output


def send(master, value):
    os.write(master, value.encode("ascii"))


def finish(pid, master, output, timeout=8):
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        waited, result = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            status = result
            break
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            try:
                output.extend(os.read(master, 4096))
            except OSError:
                pass
    if status is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        fail("console did not exit")
    try:
        os.close(master)
    except OSError:
        pass
    return os.waitstatus_to_exitcode(status)


def authenticate(binary, audit_dir, username, password):
    pid, master, tty = start_console(binary, audit_dir)
    output = bytearray()
    read_until(master, output, b"System administrator account: ")
    send(master, username + "\n")
    read_until(master, output, b"Password:")
    send(master, password + "\n")
    return pid, master, tty, output


def test_wrong_password(binary, audit_dir, username):
    pid, master, _, output = authenticate(
        binary, audit_dir, username, "incorrect-password"
    )
    read_until(master, output, b"Access denied.")
    status = finish(pid, master, output)
    if status == 0 or b"Authenticated. Entering the system root shell." in output:
        fail("wrong password entered the system root shell")
    if b"incorrect-password" in output:
        fail("password was echoed to the trusted console")


def test_root_shell(binary, audit_dir, username, password):
    pid, master, _, output = authenticate(binary, audit_dir, username, password)
    read_until(master, output, b"Authenticated. Entering the system root shell.")
    read_until(master, output, b"# ")
    send(
        master,
        "printf 'ROOT_BRIDGE_E2E uid=%s home=%s path=%s term=%s dbus=%s\\n' "
        '"$(id -u)" "$HOME" "$PATH" "$TERM" "${DBUS_SESSION_BUS_ADDRESS-unset}"; exit\n',
    )
    read_until(master, output, b"ROOT_BRIDGE_E2E")
    status = finish(pid, master, output)
    expected = (
        b"ROOT_BRIDGE_E2E uid=0 home=/root "
        b"path=/usr/sbin:/usr/bin:/sbin:/bin term=linux dbus=unset"
    )
    if expected not in output:
        fail("root shell did not receive the fixed system environment: " + repr(bytes(output)))
    if status != 0:
        fail("authorized root shell exited with status " + str(status))


def test_idle_timeout(binary, audit_dir, username, password):
    pid, master, _, output = authenticate(binary, audit_dir, username, password)
    read_until(master, output, b"Authenticated. Entering the system root shell.")
    read_until(master, output, b"# ")
    read_until(master, output, b"System root session expired after inactivity.", 9)
    status = finish(pid, master, output)
    if status != 0:
        fail("idle timeout did not close the authorized session")


def main():
    if os.geteuid() != 0:
        fail("must run as root")
    if len(sys.argv) != 5:
        fail("usage: test-root-bridge-console.py CONSOLE AUDIT_DIR USERNAME PASSWORD")
    binary, audit_dir, username, password = sys.argv[1:]
    test_wrong_password(binary, audit_dir, username)
    test_root_shell(binary, audit_dir, username, password)
    test_idle_timeout(binary, audit_dir, username, password)
    with open(os.path.join(audit_dir, "root-bridge.log"), encoding="utf-8") as audit:
        records = audit.read()
    if "outcome=failed user={}".format(username) not in records:
        fail("failed password was not audited")
    if "outcome=success user={}".format(username) not in records:
        fail("authorized root session was not audited")
    if "outcome=idle-timeout user={}".format(username) not in records:
        fail("idle timeout was not audited")
    if password in records or "incorrect-password" in records:
        fail("audit log contains credential material")
    print("system PAM console rejected bad credentials, opened a clean root shell, audited it, and enforced idle expiry")


if __name__ == "__main__":
    main()
