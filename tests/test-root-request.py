#!/usr/bin/env python3
import os
import pathlib
import socket
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/veyra-user-root-template/veyra-root-request.c"


def fail(message):
    raise SystemExit("root request test failed: " + message)


def build(binary):
    compiler = os.environ.get("CC", "cc")
    command = [
        compiler,
        "-std=c11",
        "-D_FORTIFY_SOURCE=2",
        "-O2",
        "-fPIE",
        "-pie",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wl,-z,relro,-z,now",
        "-o",
        str(binary),
        str(SOURCE),
    ]
    subprocess.run(command, check=True)


def request_once(binary, response, close_after_response=False):
    broker, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    broker_copy = os.dup(broker.fileno())
    broker.close()
    broker = socket.socket(fileno=broker_copy)
    try:
        previous_fd3 = os.dup(3)
    except OSError:
        previous_fd3 = None
    os.dup2(client.fileno(), 3)
    process = subprocess.Popen(
        [str(binary)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(3,),
    )
    if previous_fd3 is None:
        os.close(3)
    else:
        os.dup2(previous_fd3, 3)
        os.close(previous_fd3)
    client.close()
    packet = broker.recv(64)
    if packet != b"ROOTREQ1":
        stdout, stderr = process.communicate(timeout=5)
        fail(
            "helper did not send the fixed request packet: "
            + repr(packet)
            + "; exit="
            + str(process.returncode)
            + "; stderr="
            + repr(stderr)
            + "; stdout="
            + repr(stdout)
        )
    broker.send(response)
    if close_after_response:
        broker.close()
    stdout, stderr = process.communicate(timeout=5)
    if broker.fileno() >= 0:
        broker.close()
    return process.returncode, stdout, stderr


def main():
    if len(sys.argv) != 1:
        fail("this test takes no arguments")
    with tempfile.TemporaryDirectory(prefix="veyra-root-request-") as directory:
        binary = pathlib.Path(directory) / "veyra-root-request"
        build(binary)

        denied = request_once(binary, b"DENIED")
        if denied[0] != 1 or b"not authorized" not in denied[2]:
            fail("denied response was not reported safely")

        allowed = request_once(binary, b"OK")
        if allowed[0] != 0 or b"console closed" not in allowed[1]:
            fail("completed broker response was not reported")

        closed = request_once(binary, b"OK", close_after_response=True)
        if closed[0] != 0 or b"console closed" not in closed[1]:
            fail("buffered broker response was lost when the channel closed")

        missing = subprocess.run(
            [str(binary)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if missing.returncode != 1 or b"managed session control is unavailable" not in missing.stderr:
            fail("helper accepted a process without the session control descriptor")

    print("root request helper sends only the fixed packet and handles broker denial, completion, and missing-session state")


if __name__ == "__main__":
    main()
