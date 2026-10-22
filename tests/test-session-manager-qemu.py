#!/usr/bin/env python3
"""Exercise real PAM login and per-account user-root persistence in QEMU."""
import argparse
import pathlib
import re
import shutil
import sys

import pexpect


LOGIN = re.compile(rb"(?im)^(?:login|username):[ \t]*\r?$")
PASSWORD = re.compile(rb"(?i)password:\s*$")
SHELL = re.compile(rb"[$#] ")
TEST_PASSWORD = b"Veyra-Session-QEMU-2026!"


def wait_for_login(guest, timeout=240):
    guest.expect(LOGIN, timeout=timeout)


def authenticate(guest, password):
    guest.sendline(b"veyraqa")
    guest.expect(PASSWORD, timeout=30)
    guest.sendline(password)


def disable_terminal_echo(guest):
    guest.sendline(b"stty -echo")
    guest.expect(SHELL, timeout=20)


def run_shell_command(guest, command, marker):
    guest.sendline(command)
    guest.expect(marker, timeout=45)
    transcript = guest.before + guest.after
    guest.expect(SHELL, timeout=20)
    return transcript


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
    command = [
        "-machine", "q35,accel=tcg", "-m", "1024", "-smp", "2",
        "-nodefaults", "-nographic", "-no-reboot",
        "-serial", "stdio", "-monitor", "none",
        "-kernel", str(args.kernel.resolve()),
        "-initrd", str(args.initramfs.resolve()),
        "-drive", f"file={args.system_disk.resolve()},if=virtio,format=raw,cache=writeback",
        "-drive", f"file={args.user_store_disk.resolve()},if=virtio,format=raw,cache=writeback",
        "-append", "root=/dev/vda rootfstype=ext4 rootwait console=ttyS0,115200 panic=1",
    ]

    with args.log.open("wb") as logfile:
        guest = pexpect.spawn(qemu, command, encoding=None, timeout=240)
        guest.logfile_read = logfile
        try:
            wait_for_login(guest)

            authenticate(guest, b"wrong-password")
            outcome = guest.expect([LOGIN, SHELL], timeout=60)
            if outcome != 0:
                raise RuntimeError("the guest accepted a wrong system password")

            authenticate(guest, TEST_PASSWORD)
            guest.expect(SHELL, timeout=90)
            disable_terminal_echo(guest)
            proof = run_shell_command(
                guest,
                b"printf 'VEYRA_QEMU_SESSION_PROOF\\n'; id -u; echo PID=$$; "
                b"cat /proc/self/uid_map; "
                b"if test -e /dev/vda; then echo HOST_DEVICE_VISIBLE; else echo HOST_DEVICE_HIDDEN; fi; "
                b"if test -S /run/veyra-session-manager/control.sock; then "
                b"echo HOST_SOCKET_VISIBLE; else echo HOST_SOCKET_HIDDEN; fi; "
                b"if sudo -n true >/dev/null 2>&1; then echo INNER_SUDO_UNEXPECTED; "
                b"else echo INNER_SUDO_DENIED; fi; "
                b"printf 'persistent-home\\n' > \"$HOME/veyra-qemu-proof\"; "
                b"echo VEYRA_QEMU_SESSION_PROOF_END",
                b"VEYRA_QEMU_SESSION_PROOF_END",
            )
            for expected in (
                b"VEYRA_QEMU_SESSION_PROOF",
                b"1000",
                b"PID=1",
                b"HOST_DEVICE_HIDDEN",
                b"HOST_SOCKET_HIDDEN",
                b"INNER_SUDO_DENIED",
            ):
                if expected not in proof:
                    raise RuntimeError(f"missing isolated-session evidence: {expected!r}")
            if re.search(rb"(?m)^\s*0\s+300000\s+65536\s*$", proof) is None:
                raise RuntimeError("the isolated user namespace UID map is incorrect")

            guest.sendline(b"exit")
            wait_for_login(guest, timeout=90)

            authenticate(guest, TEST_PASSWORD)
            guest.expect(SHELL, timeout=90)
            disable_terminal_echo(guest)
            persistence = run_shell_command(
                guest,
                b"cat \"$HOME/veyra-qemu-proof\"; echo VEYRA_QEMU_PERSISTENCE_PASS",
                b"VEYRA_QEMU_PERSISTENCE_PASS",
            )
            if b"persistent-home" not in persistence:
                raise RuntimeError("the separate home volume did not survive relogin")

            guest.sendline(b"exit")
            wait_for_login(guest, timeout=90)
        finally:
            guest.close(force=True)

    print(
        "VEYRA_SESSION_MANAGER_QEMU_PASS: wrong password rejected; PAM login entered "
        "a mapped user namespace; host device/socket and inner sudo stayed unavailable; "
        "the separate home persisted across logout and relogin"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, pexpect.ExceptionPexpect) as error:
        print(f"VEYRA_SESSION_MANAGER_QEMU_FAIL: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
