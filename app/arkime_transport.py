"""Isolated HTTPS transport for one bounded Arkime Sessions API request."""
from __future__ import annotations

import json
import ssl
import sys
from urllib import error, parse, request

from app.arkime_evidence import MAX_ARKIME_JSON_BYTES


class ArkimeTransportError(RuntimeError):
    pass


class _RejectRedirects(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ArkimeTransportError(
            "Arkime redirected the Sessions API request; redirects are refused"
        )


def fetch_sessions(payload: dict) -> bytes:
    base_url = payload["base_url"]
    sessions_url = f"{base_url}/api/sessions"
    username = payload["username"]
    password_file = payload["password_file"]
    ca_file = payload.get("ca_file")
    timeout_seconds = payload["timeout_seconds"]
    parameters = payload["parameters"]
    try:
        with open(password_file, "r", encoding="utf-8") as handle:
            password = handle.read(4097).strip()
    except (OSError, UnicodeError) as exc:
        raise ArkimeTransportError("Arkime password file could not be read") from exc
    if not password:
        raise ArkimeTransportError("Arkime password file is empty")
    if len(password.encode("utf-8")) > 4096:
        raise ArkimeTransportError("Arkime password file exceeds 4 KiB")
    password_manager = request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, base_url, username, password)
    context = ssl.create_default_context(cafile=ca_file)
    opener = request.build_opener(
        request.ProxyHandler({}), _RejectRedirects(),
        request.HTTPDigestAuthHandler(password_manager),
        request.HTTPSHandler(context=context),
    )
    outbound = request.Request(
        f"{sessions_url}?{parse.urlencode(parameters)}", method="GET",
        headers={
            "Accept": "application/json", "Accept-Encoding": "identity",
            "User-Agent": "NCT-Arkime-Connector/1",
        },
    )
    try:
        with opener.open(outbound, timeout=timeout_seconds) as response:
            encoding = (response.headers.get("Content-Encoding") or "identity").lower().strip()
            if encoding not in {"", "identity"}:
                raise ArkimeTransportError(
                    "Arkime returned compressed content even though identity encoding was required"
                )
            chunks = []
            total = 0
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    return b"".join(chunks)
                total += len(chunk)
                if total > MAX_ARKIME_JSON_BYTES:
                    raise ArkimeTransportError(
                        "Arkime response exceeded the 10 MiB pull limit; no evidence was published"
                    )
                chunks.append(chunk)
    except ArkimeTransportError:
        raise
    except error.HTTPError as exc:
        if exc.code in {301, 302, 303, 307, 308}:
            detail = "Arkime redirected the Sessions API request; redirects are refused"
        elif exc.code in {401, 403}:
            detail = "Arkime rejected the read-only account credentials or permissions"
        else:
            detail = f"Arkime returned HTTP {exc.code}"
        raise ArkimeTransportError(detail) from exc
    except (error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        raise ArkimeTransportError("Arkime could not be reached with verified HTTPS") from exc
    finally:
        password = ""


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(64 * 1024)
        payload = json.loads(raw.decode("utf-8"))
        content = fetch_sessions(payload)
        sys.stdout.buffer.write(content)
        sys.stdout.buffer.flush()
        return 0
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        sys.stderr.write(detail[:500])
        sys.stderr.flush()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
