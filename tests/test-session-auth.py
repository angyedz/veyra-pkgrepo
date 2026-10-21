import os
import pty
import fcntl
import select
import signal
import subprocess
import sys
import termios
import time


def fail(message):
    raise SystemExit("session auth test failed: " + message)


def launch(driver, running):
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
            os.execv(driver, [driver, "nobody", tty])
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


def stop_all(running):
    for pid, master in running:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        try:
            os.close(master)
        except OSError:
            pass


def main():
    if os.geteuid() != 0:
        fail("must run as root")
    if len(sys.argv) != 4:
        fail("usage: test-session-auth.py DRIVER CONSUMER MAPPING_FILE")

    driver, consumer, mapping_file = sys.argv[1:]
    running = []
    try:
        pid, _, token = launch(driver, running)

        wrong_pid = consume(consumer, token, os.getpid())
        if wrong_pid.returncode == 0:
            fail("grant accepted a different peer PID")

        accepted = consume(consumer, token, pid)
        expected_prefix = "authorized\tnobody\t65534\t65534\t300000\t"
        if accepted.returncode != 0 or not accepted.stdout.startswith(expected_prefix):
            fail("valid grant was rejected: " + accepted.stderr.strip())

        replay = consume(consumer, token, pid)
        if replay.returncode == 0:
            fail("one-use grant was accepted twice")

        revoked_pid, _, revoked_token = launch(driver, running)
        with open(mapping_file, "w", encoding="ascii") as mapping:
            mapping.write("400000\n")
        revoked = consume(consumer, revoked_token, revoked_pid)
        if revoked.returncode == 0:
            fail("grant survived an account mapping change")
        os.unlink(mapping_file)

        expired_pid, _, expired_token = launch(driver, running)
        time.sleep(2)
        expired = consume(consumer, expired_token, expired_pid)
        if expired.returncode == 0:
            fail("expired grant was accepted")

        print("session auth rejects wrong PID, mapping changes, replay and expiry")
    finally:
        stop_all(running)


if __name__ == "__main__":
    main()
