"""Drive the real wizard on a PTY in the public netlab namespace."""

import json
import os
import pty
import select
import signal
import subprocess
import sys
import termios
import time
from pathlib import Path


def wizard(command, work, token, interrupt=False):
    master, slave = pty.openpty()
    with subprocess.Popen(command, stdin=slave, stderr=slave, stdout=subprocess.PIPE) as child:
        transcript = bytearray()
        pending = bytearray()

        def expect(fragment):
            deadline = time.monotonic() + 15
            while fragment not in pending:
                ready, _, _ = select.select([master], [], [], max(0, deadline - time.monotonic()))
                if not ready:
                    raise AssertionError(f"timeout waiting for {fragment!r}")
                chunk = os.read(master, 65536)
                pending.extend(chunk)
                transcript.extend(chunk)
            del pending[: pending.index(fragment) + len(fragment)]

        try:
            for label, answer in [
                (b"Uplink interface", b"nwl-h0"),
                (b"UDP listen port", b""),
                (b"STUN servers", b"45.78.0.1:3478 45.78.0.3:3478"),
                (b"Server mode", b""),
                (b"Server tunnel", b""),
                (b"LANs (", b"10.88.0.0/24,10.89.0.0/24"),
                (b"Cloudflare zone", b"example.net"),
                (b"Full DNS record", b"home.example.net"),
                (b"Cloudflare API token (hidden)", token),
                (b"First peer name", b"phone"),
                (b"Peer format", b"surge"),
                (b"Install and start", b"no"),
            ]:
                expect(label)
                if interrupt and label == b"Server mode":
                    child.send_signal(signal.SIGINT)
                    assert child.wait(5) == -signal.SIGINT
                    assert not (work / "server.json").exists()
                    return
                if answer == token:
                    deadline = time.monotonic() + 2
                    while termios.tcgetattr(slave)[3] & termios.ECHO:
                        assert time.monotonic() < deadline, "terminal still echoes the token"
                        time.sleep(0.005)
                os.write(master, answer + b"\n")
            stdout, _ = child.communicate(timeout=10)
            while select.select([master], [], [], 0)[0]:
                transcript.extend(os.read(master, 65536))
            assert child.returncode == 0
            assert token not in transcript and token not in stdout
            assert termios.tcgetattr(slave)[3] & termios.ECHO
            assert stdout.startswith(b"[Proxy]") and b"home.example.net:51830" in stdout
            server = json.loads((work / "server.json").read_text())["role"]["server"]
            assert server["cloudflare"]["token"].encode() == token
            assert server["lan"] == ["10.88.0.0/24", "10.89.0.0/24"]
        finally:
            if child.poll() is None:
                child.kill()
            os.close(master)
            os.close(slave)


if __name__ == "__main__":
    binary, directory = sys.argv[1:]
    work = Path(directory)
    args = [binary, "init", "--config", str(work / "server.json")]
    wizard(args, work, b"synthetic-hidden-token", interrupt=True)
    wizard(args, work, b"synthetic-hidden-token")
