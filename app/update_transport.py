"""Local Unix-socket transport. The application never receives the Docker socket."""
from __future__ import annotations

import http.client
import json
import socket


class LocalConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 30):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def local_request(path: str, method: str, route: str, body=None, *, token="", stream=None, size=0):
    connection = LocalConnection(path, timeout=1800 if route == "/upload" else 90)
    headers = {"Content-Type": "application/json", "Authorization": "Bearer " + token}
    payload = json.dumps(body or {}).encode()
    if stream is not None:
        payload = stream
        headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(size)})
    try:
        connection.request(method, route, body=payload, headers=headers)
        response = connection.getresponse()
        raw = response.read(2 * 1024**2 + 1)
        if len(raw) > 2 * 1024**2:
            raise ValueError("Recovery helper response exceeds its limit")
        result = json.loads(raw)
        if response.status >= 400:
            raise ValueError(result.get("detail", "Recovery helper refused this action"))
        return result
    finally:
        connection.close()
