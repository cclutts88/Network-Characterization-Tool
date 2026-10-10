"""Minimal TCP relay used only by the isolated Phase 0 browser controller."""
from __future__ import annotations

import argparse
import select
import socket
import socketserver


def split_endpoint(value: str) -> tuple[str, int]:
    host, separator, raw_port = value.rpartition(":")
    if not separator or not host or not raw_port.isdigit():
        raise ValueError(f"Invalid endpoint: {value}")
    return host, int(raw_port)


class Relay(socketserver.BaseRequestHandler):
    upstream: tuple[str, int]

    def handle(self) -> None:
        with socket.create_connection(self.upstream, timeout=30) as target:
            peers = {self.request: target, target: self.request}
            while True:
                readable, _, _ = select.select(list(peers), [], [], 30)
                if not readable:
                    return
                for source in readable:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    peers[source].sendall(chunk)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="0.0.0.0:8080")
    parser.add_argument("--upstream", required=True)
    args = parser.parse_args()
    listen = split_endpoint(args.listen)
    Relay.upstream = split_endpoint(args.upstream)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(listen, Relay) as server:
        server.daemon_threads = True
        server.serve_forever()


if __name__ == "__main__":
    main()
