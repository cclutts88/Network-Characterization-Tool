import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import socket
import socketserver
import threading

import pytest
from fastapi.testclient import TestClient

from app.update_transport import LocalRequestError, local_request


@pytest.fixture
def helper_socket(tmp_path):
    if not hasattr(socket, 'AF_UNIX'):
        pytest.skip('Unix sockets unavailable')
    reply = {'status': 200, 'raw': b'{}'}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            self.send_response(reply['status'])
            self.send_header('Content-Length', str(len(reply['raw'])))
            self.end_headers()
            self.wfile.write(reply['raw'])

    path = str(tmp_path / 'helper.sock')
    server = socketserver.UnixStreamServer(path, Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield path, reply
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.mark.parametrize('status,access', [(403, True), (409, False)])
def test_real_helper_rejection_retains_auth_distinction(helper_socket, monkeypatch, status, access):
    import app.recovery_console as console
    path, reply = helper_socket
    reply.update(status=status, raw=json.dumps({'detail': 'Fixture rejection'}).encode())
    with pytest.raises(LocalRequestError) as error:
        local_request(path, 'GET', '/status')
    assert isinstance(error.value, ValueError) and error.value.status_code == status
    monkeypatch.setenv('NCT_RECOVERY_SOCKET', path)
    result = TestClient(console.app).get('/api/status')
    assert result.status_code == status
    assert result.json()['access_required'] is access


def test_connection_failure_never_requests_new_access(tmp_path, monkeypatch):
    import app.recovery_console as console
    monkeypatch.setenv('NCT_RECOVERY_SOCKET', str(tmp_path / 'missing.sock'))
    response = TestClient(console.app).get('/api/status')
    assert response.status_code == 503
    assert response.json().get('access_required') is not True
    assert 'not cancelled' in response.json()['detail']


@pytest.mark.parametrize('raw', [b'null', b'[]', b'not JSON', b'x' * (2 * 1024**2 + 1)])
def test_invalid_helper_payload_is_not_auth_failure(helper_socket, monkeypatch, raw):
    import app.recovery_console as console
    path, reply = helper_socket
    reply.update(raw=raw, status=200)
    monkeypatch.setenv('NCT_RECOVERY_SOCKET', path)
    response = TestClient(console.app).get('/api/status')
    assert response.status_code == 409
    assert response.json().get('access_required') is not True


def test_browser_origin_refusal_is_not_helper_auth(monkeypatch):
    import app.recovery_console as console
    monkeypatch.setattr(console, 'local_request', lambda *a, **k: pytest.fail('Origin rejection reached helper'))
    response = TestClient(console.app).post('/api/exchange', json={'code': 'fixture'},
        headers={'Origin': 'https://unrelated.test', 'X-NCT-Recovery': '1'})
    assert response.status_code == 403 and response.json().get('access_required') is not True
