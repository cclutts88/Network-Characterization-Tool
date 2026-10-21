"""Real socket fixture used to prove the parent Arkime deadline kills transport."""
from __future__ import annotations

import http.client
import socket
import sys
import threading
import time


def main() -> None:
    mode = sys.argv[1]
    sys.stdin.buffer.read()
    left, right = socket.socketpair()

    def send() -> None:
        try:
            header = (
                b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n"
                b"Content-Encoding: identity\r\n\r\n"
            )
            if mode == "headers":
                for byte in header:
                    time.sleep(0.04)
                    right.sendall(bytes((byte,)))
            else:
                right.sendall(header)
                for _ in range(20):
                    time.sleep(0.04)
                    right.sendall(b"x")
        except OSError:
            pass
        finally:
            right.close()

    threading.Thread(target=send, daemon=True).start()
    response = http.client.HTTPResponse(left)
    response.begin()
    response.read()


if __name__ == "__main__":
    main()
