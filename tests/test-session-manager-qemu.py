#!/usr/bin/env python3
"""Exercise PAM login, concurrent user roots and manager restart in QEMU."""
import argparse
import pathlib
import re
import shutil
import socket
import sys
import tempfile
import time

import pexpect
from pexpect.fdpexpect import fdspawn


LOGIN = re.compile(
    rb"(?im)^(?:(?:\([^)]+\)|[A-Za-z0-9_.-]+)[ \t]+)?"
    rb"(?:login|username):[ \t]*\r?$"
)
PASSWORD = re.compile(rb"(?i)password:\s*$")
SHELL = re.compile(rb"[$#] ")
TEST_USERS = (
    (b"veyraqa", b"veyraqa2026", 300000),
    (b"veyraqa2", b"Veyra-Session-QEMU-Second-2026!", 400000),
)


def wait_for_login(guest, timeout=240, context=""):
    try:
        guest.expect(LOGIN, timeout=timeout)
    except pexpect.TIMEOUT as error:
        label = f" {context}" if context else ""
        raise RuntimeError(f"timed out waiting for login prompt{label}") from error


def authenticate(guest, account, password):
    guest.sendline(account)
    guest.expect(PASSWORD, timeout=30)
    guest.sendline(password)


def disable_terminal_echo(guest):
    guest.sendline(b"stty -echo")
    guest.expect(SHELL, timeout=20)


def run_shell_command(guest, command, marker):
    guest.sendline(command)
    guest.expect(marker, timeout=60)
    transcript = guest.before + guest.after
    guest.expect(SHELL, timeout=20)
    return transcript


def connect_serial(path, logfile, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(str(path))
            guest = fdspawn(connection.detach(), encoding=None, timeout=240)
            guest.logfile_read = logfile
            return guest
        except (FileNotFoundError, ConnectionRefusedError):
            connection.close()
            time.sleep(0.1)
    raise RuntimeError(f"QEMU serial socket did not become available: {path}")


def read_hmp_response(monitor, timeout=10):
    deadline = time.monotonic() + timeout
    response = bytearray()
    while b"(qemu) " not in response:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("QEMU monitor did not return its prompt")
        monitor.settimeout(remaining)
        chunk = monitor.recv(4096)
        if not chunk:
            raise RuntimeError("QEMU monitor disconnected")
        response.extend(chunk)
    return bytes(response)


def connect_hmp_monitor(path, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        monitor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            monitor.connect(str(path))
            read_hmp_response(monitor)
            return monitor
        except (FileNotFoundError, ConnectionRefusedError):
            monitor.close()
            time.sleep(0.1)
    raise RuntimeError(f"QEMU monitor socket did not become available: {path}")


def hmp_command(monitor, command):
    monitor.sendall(command + b"\n")
    response = read_hmp_response(monitor)
    if b"unknown key" in response.lower() or b"error:" in response.lower():
        raise RuntimeError(f"QEMU monitor rejected command: {response!r}")
    return response


def send_virtual_keys(monitor, text):
    key_names = {" ": "spc", "-": "minus", "\n": "ret"}
    for character in text:
        key_name = key_names.get(character, character)
        hmp_command(monitor, b"sendkey " + key_name.encode("ascii") + b" 50")
        # HMP schedules key release asynchronously; leave enough time before
        # pressing the next key so guest input cannot merge adjacent strokes.
        time.sleep(0.1)


def wait_for_control_condition(guest, condition, label, timeout=90):
    marker = f"VEYRA_CONTROL_CONDITION_PASS_{label}".encode("ascii")
    failed = f"VEYRA_CONTROL_CONDITION_FAIL_{label}".encode("ascii")
    limit = str(timeout).encode("ascii")
    command = (
        b"i=0; while test \"$i\" -lt " + limit + b"; do if " + condition +
        b"; then echo " + marker + b"; break; fi; sleep 1; i=$((i+1)); done; "
        b"test \"$i\" -lt " + limit + b" || echo " + failed
    )
    guest.sendline(command)
    outcome = guest.expect([marker, failed], timeout=timeout + 20)
    guest.expect(SHELL, timeout=20)
    if outcome != 0:
        raise RuntimeError(f"timed out waiting for QEMU guest condition: {label}")


def wait_for_vt(guest, number, timeout=90):
    device = f"tty{number}".encode("ascii")
    condition = b"test \"$(cat /sys/class/tty/tty0/active 2>/dev/null)\" = " + device
    wait_for_control_condition(guest, condition, f"active_vt_{number}", timeout)


def wait_for_console_text(guest, number, text, timeout=90):
    device = f"/dev/vcs{number}".encode("ascii")
    quoted_text = b"'" + text.encode("ascii") + b"'"
    condition = b"grep -aF -q " + quoted_text + b" " + device
    label = re.sub(
        r"[^A-Za-z0-9_]+", "_",
        f"console_text_vt{number}_{text.split()[0].lower()}",
    )
    try:
        wait_for_control_condition(guest, condition, label, timeout)
    except RuntimeError:
        marker = f"VEYRA_VT{number}_SCREEN_CAPTURE_END".encode("ascii")
        dump = run_shell_command(
            guest,
            b"cat " + device + b" | tr -d '\\000' | fold -w 80 | tail -n 5; "
            b"echo " + marker,
            marker,
        )
        print(
            f"VEYRA_VT{number}_SCREEN_CAPTURE: {dump!r}",
            file=sys.stderr,
            flush=True,
        )
        raise


def prove_root_bridge_success(monitor, control):
    # A real system virtual terminal is required; the serial sessions above
    # must remain ineligible even though the same account is allowlisted.
    wait_for_vt(control, 1)
    wait_for_console_text(control, 1, "login:")
    send_virtual_keys(monitor, "veyraqa\n")
    wait_for_console_text(control, 1, "Password:")
    send_virtual_keys(monitor, TEST_USERS[0][1].decode("ascii") + "\n")
    wait_for_console_text(control, 1, "$", timeout=120)
    send_virtual_keys(monitor, "veyra-root-request\n")
    wait_for_vt(control, 9)
    wait_for_console_text(control, 9, "System administrator account:")
    send_virtual_keys(monitor, "veyraqa\n")
    wait_for_console_text(control, 9, "Password:")
    send_virtual_keys(monitor, TEST_USERS[0][1].decode("ascii") + "\n")
    wait_for_console_text(control, 9, "Authenticated. Entering the system root shell.")
    send_virtual_keys(monitor, "id\n")
    wait_for_console_text(control, 9, "uid=0(root)")
    send_virtual_keys(monitor, "exit\n")
    wait_for_vt(control, 1)
    wait_for_console_text(control, 1, "System administrator console closed.")
    proof = run_shell_command(
        control,
        b"grep -q 'outcome=success user=veyraqa tty=/dev/tty9' "
        b"/var/log/veyra/root-bridge.log && echo "
        b"VEYRA_ROOT_BRIDGE_AUTHORIZED_QEMU_PASS",
        b"VEYRA_ROOT_BRIDGE_AUTHORIZED_QEMU_PASS",
    )
    if b"VEYRA_ROOT_BRIDGE_AUTHORIZED_QEMU_PASS" not in proof:
        raise RuntimeError("the successful system-root PAM login was not audited")


def login_user(guest, account, password, timeout=90, context=""):
    wait_for_login(
        guest,
        timeout=timeout,
        context=context or f"for {account.decode('ascii')}",
    )
    authenticate(guest, account, password)
    guest.expect(SHELL, timeout=timeout)
    disable_terminal_echo(guest)


def prove_user_session(guest, account, uid_base):
    name = account.decode("ascii")
    marker = f"VEYRA_SESSION_PROOF_END_{name}".encode("ascii")
    command = (
        b"printf 'VEYRA_SESSION_PROOF\\n'; id -u; id -un; echo PID=$$; "
        b"cat /proc/self/uid_map; "
        b"if test -e /dev/vda; then echo HOST_DEVICE_VISIBLE; else echo HOST_DEVICE_HIDDEN; fi; "
        b"if test -S /run/veyra-session-manager/control.sock; then "
        b"echo HOST_SOCKET_VISIBLE; else echo HOST_SOCKET_HIDDEN; fi; "
        b"if sudo -n true >/dev/null 2>&1; then echo INNER_SUDO_UNEXPECTED; "
        b"else echo INNER_SUDO_DENIED; fi; "
        b"printf 'persistent-home-" + account + b"\\n' > \"$HOME/veyra-qemu-proof\"; "
        b"echo " + marker
    )
    proof = run_shell_command(guest, command, marker)
    for expected in (
        b"VEYRA_SESSION_PROOF",
        b"1000",
        account,
        b"HOST_DEVICE_HIDDEN",
        b"HOST_SOCKET_HIDDEN",
        b"INNER_SUDO_DENIED",
    ):
        if expected not in proof:
            raise RuntimeError(f"missing isolated-session evidence for {name}: {expected!r}")
    expected_map = rb"(?m)^\s*0\s+" + str(uid_base).encode("ascii") + rb"\s+65536\s*$"
    if re.search(expected_map, proof) is None:
        raise RuntimeError(f"the isolated UID map for {name} is incorrect")


def prove_root_bridge_denies_unlisted_account(guest):
    marker = b"VEYRA_ROOT_BRIDGE_POLICY_DENIAL_PASS"
    command = (
        b"if veyra-root-request >/tmp/veyra-root-request.log 2>&1; then "
        b"echo ROOT_BRIDGE_UNEXPECTED_SUCCESS; else "
        b"cat /tmp/veyra-root-request.log; "
        b"grep -q 'this system account is not authorized' "
        b"/tmp/veyra-root-request.log && echo " + marker + b"; fi"
    )
    transcript = run_shell_command(guest, command, marker)
    if marker not in transcript:
        raise RuntimeError(
            "the system manager did not deny the unlisted account's root-console request"
        )


def prove_root_bridge_rejects_serial_tty(guest):
    marker = b"VEYRA_ROOT_BRIDGE_SERIAL_TTY_DENIAL_PASS"
    command = (
        b"if veyra-root-request >/tmp/veyra-root-request.log 2>&1; then "
        b"echo ROOT_BRIDGE_UNEXPECTED_SUCCESS; else "
        b"cat /tmp/veyra-root-request.log; "
        b"grep -q 'no trusted local system console is available' "
        b"/tmp/veyra-root-request.log && echo " + marker + b"; fi"
    )
    transcript = run_shell_command(guest, command, marker)
    if marker not in transcript:
        raise RuntimeError(
            "the system manager did not reject an allowlisted account's serial-TTY request"
        )


def prove_persistent_home(guest, account):
    name = account.decode("ascii")
    marker = f"VEYRA_SESSION_PERSISTENCE_PASS_{name}".encode("ascii")
    content = b"persistent-home-" + account
    transcript = run_shell_command(
        guest,
        b"cat \"$HOME/veyra-qemu-proof\"; echo " + marker,
        marker,
    )
    if content not in transcript:
        raise RuntimeError(f"the separate home for {name} did not persist across session restart")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kernel", type=pathlib.Path)
    parser.add_argument("initramfs", type=pathlib.Path)
    parser.add_argument("system_disk", type=pathlib.Path)
    parser.add_argument("user_store_disk", type=pathlib.Path)
    parser.add_argument("--log", type=pathlib.Path, required=True)
    args = parser.parse_args()

    qemu = shutil.which("qemu-system-x86_64")
    images = (args.kernel, args.initramfs, args.system_disk, args.user_store_disk)
    if not qemu or not all(path.is_file() for path in images):
        parser.error("QEMU, kernel, initramfs and both ext4 disks are required")

    args.log.parent.mkdir(parents=True, exist_ok=True)
    tty1_log_path = args.log.with_name(args.log.stem + "-ttyS1.log")
    tty2_log_path = args.log.with_name(args.log.stem + "-ttyS2.log")
    with tempfile.TemporaryDirectory(prefix="veyra-session-qemu-") as socket_dir:
        tty1_socket = pathlib.Path(socket_dir) / "ttyS1.sock"
        tty2_socket = pathlib.Path(socket_dir) / "ttyS2.sock"
        monitor_socket = pathlib.Path(socket_dir) / "monitor.sock"
        command = [
            "-machine", "q35,accel=tcg", "-m", "1024", "-smp", "2",
            "-nodefaults", "-display", "none", "-no-reboot",
            "-device", "VGA",
            "-device", "qemu-xhci,id=xhci",
            "-device", "usb-kbd,bus=xhci.0",
            "-serial", "stdio",
            "-chardev", f"socket,id=serial1,path={tty1_socket},server=on,wait=off",
            "-serial", "chardev:serial1",
            "-chardev", f"socket,id=serial2,path={tty2_socket},server=on,wait=off",
            "-serial", "chardev:serial2",
            "-monitor", f"unix:{monitor_socket},server=on,wait=off",
            "-kernel", str(args.kernel.resolve()),
            "-initrd", str(args.initramfs.resolve()),
            "-drive", f"file={args.system_disk.resolve()},if=virtio,format=raw,cache=writeback",
            "-drive", f"file={args.user_store_disk.resolve()},if=virtio,format=raw,cache=writeback",
            "-append", "root=/dev/vda rootfstype=ext4 rootwait console=ttyS0,115200 panic=1",
        ]

        with args.log.open("wb") as log0, tty1_log_path.open("wb") as log1, \
                tty2_log_path.open("wb") as log2:
            guest0 = pexpect.spawn(qemu, command, encoding=None, timeout=240)
            guest0.logfile_read = log0
            guest1 = None
            guest2 = None
            monitor = None
            try:
                guest1 = connect_serial(tty1_socket, log1)
                guest2 = connect_serial(tty2_socket, log2)
                monitor = connect_hmp_monitor(monitor_socket)

                # The system login service rejects a bad password before it
                # starts either account's isolated environment.
                wait_for_login(guest0)
                authenticate(guest0, TEST_USERS[0][0], b"wrong-password")
                outcome = guest0.expect([LOGIN, SHELL], timeout=60)
                if outcome != 0:
                    raise RuntimeError("the guest accepted a wrong system password")

                authenticate(guest0, TEST_USERS[0][0], TEST_USERS[0][1])
                guest0.expect(SHELL, timeout=90)
                disable_terminal_echo(guest0)
                prove_user_session(guest0, TEST_USERS[0][0], TEST_USERS[0][2])
                prove_root_bridge_rejects_serial_tty(guest0)

                # A second standard Linux account must use a separate mapped
                # root and home while the first account remains active.
                login_user(guest1, TEST_USERS[1][0], TEST_USERS[1][1])
                prove_user_session(guest1, TEST_USERS[1][0], TEST_USERS[1][2])
                prove_root_bridge_denies_unlisted_account(guest1)

                # This disposable root shell is only a test control console;
                # the user-facing sessions above still use PAM login.
                guest2.expect(SHELL, timeout=90)
                disable_terminal_echo(guest2)

                # A managed user on a real virtual terminal must be able to
                # authenticate at VT9, receive a root shell, and return to VT1.
                prove_root_bridge_success(monitor, guest2)

                # Killing the host-owned login frontend simulates an
                # unexpected terminal/client disconnect while its user shell
                # is still alive. The manager must tear down that session.
                disconnect = run_shell_command(
                    guest2,
                    b"pid=$(cat /run/veyra-qemu-login-ttyS1.pid); "
                    b"test \"$pid\" -gt 1 && kill \"$pid\" && "
                    b"echo VEYRA_SESSION_DISCONNECT_PASS",
                    b"VEYRA_SESSION_DISCONNECT_PASS",
                )
                if b"VEYRA_SESSION_DISCONNECT_PASS" not in disconnect:
                    raise RuntimeError("the test could not disconnect a user login frontend")
                login_user(guest1, TEST_USERS[1][0], TEST_USERS[1][1], timeout=90)
                prove_persistent_home(guest1, TEST_USERS[1][0])

                # Both accounts are active again when the system manager is
                # restarted, exercising worker termination and cleanup.
                restart = run_shell_command(
                    guest2,
                    b"rc-service veyra-session-manager restart && "
                    b"echo VEYRA_SESSION_MANAGER_RESTART_PASS",
                    b"VEYRA_SESSION_MANAGER_RESTART_PASS",
                )
                if b"VEYRA_SESSION_MANAGER_RESTART_PASS" not in restart:
                    raise RuntimeError("the system manager did not restart cleanly")

                # Manager shutdown must end both isolated sessions and allow
                # fresh authenticated sessions after the service returns.
                login_user(guest0, TEST_USERS[0][0], TEST_USERS[0][1], timeout=90)
                prove_persistent_home(guest0, TEST_USERS[0][0])
                login_user(guest1, TEST_USERS[1][0], TEST_USERS[1][1], timeout=90)
                prove_persistent_home(guest1, TEST_USERS[1][0])

                # Normal logout also closes the session and returns to the
                # system login prompt without losing the account's home.
                guest1.sendline(b"exit")
                login_user(
                    guest1,
                    TEST_USERS[1][0],
                    TEST_USERS[1][1],
                    timeout=90,
                    context="after user logout",
                )
                prove_persistent_home(guest1, TEST_USERS[1][0])

                guest0.sendline(b"exit")
                wait_for_login(guest0, timeout=90, context="after first user logout")
            finally:
                if guest1 is not None:
                    guest1.close()
                if guest2 is not None:
                    guest2.close()
                if monitor is not None:
                    monitor.close()
                guest0.close(force=True)

    print(
        "VEYRA_SESSION_MANAGER_QEMU_PASS: wrong password rejected; two ordinary system "
        "accounts ran concurrently in separate mapped roots; an allowlisted serial-TTY "
        "request and an unlisted account's request could not trigger the system-root "
        "console; the authorized VT9 PAM login opened a UID 0 shell and restored VT1; "
        "client disconnect, manager restart and logout ended sessions; both separate "
        "homes persisted"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, pexpect.ExceptionPexpect) as error:
        print(f"VEYRA_SESSION_MANAGER_QEMU_FAIL: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
