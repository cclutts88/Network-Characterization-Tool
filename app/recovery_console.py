"""Independent GUI; the only host mount is its narrow management socket."""
import os
import asyncio
from tempfile import TemporaryFile

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app.update_transport import local_request
from app.update_ui import console_page

app = FastAPI(title="NCT Recovery Console", docs_url=None, redoc_url=None, openapi_url=None)
COOKIE = "nct_recovery_session"
MAX_UPLOAD = 12 * 1024**3
upload_lock = asyncio.Lock()


@app.middleware("http")
async def boundary(request, call_next):
    if request.method not in {"GET", "HEAD"}:
        origin = request.headers.get("origin")
        if (origin and origin.rstrip("/") != str(request.base_url).rstrip("/")) or request.headers.get("x-nct-recovery") != "1":
            return JSONResponse({"detail": "Use the recovery workspace controls on this host"}, status_code=403)
    response = await call_next(request)
    response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"})
    return response


@app.get("/")
def index():
    return console_page()


@app.get("/health")
def health():
    try:
        return local_request(os.environ.get("NCT_RECOVERY_SOCKET", "/run/nct-recovery/control.sock"), "GET", "/ready")
    except (OSError, ValueError):
        return JSONResponse({"contract": "nct-update-v1", "status": "helper_unavailable"}, status_code=503)


@app.api_route("/api/{action}", methods=["GET", "POST"])
async def proxy(action: str, request: Request):
    methods = {"status": "GET", "diagnose": "GET", **{name: "POST" for name in
        ("exchange", "upload", "apply", "rollback", "verify-sign-in", "verify-backup", "start", "stop", "restart", "close", "prepare-repair", "apply-repair", "cancel-repair")}}
    if methods.get(action) != request.method:
        return JSONResponse({"detail": "Unsupported recovery action"}, status_code=404)
    token = request.cookies.get(COOKIE, "")
    socket = os.environ.get("NCT_RECOVERY_SOCKET", "/run/nct-recovery/control.sock")
    try:
        if action == "upload":
            length = int(request.headers.get("content-length", "0"))
            if not 0 < length <= MAX_UPLOAD:
                raise ValueError("Choose a package smaller than 12 GiB")
            # Authenticate before accepting a potentially large body.
            state = await run_in_threadpool(local_request, socket, "GET", "/status", token=token)
            if length > state["upload_available_bytes"]:
                raise ValueError("Insufficient private upload space. Preserve backups and archive completed packages before retrying.")
            if upload_lock.locked():
                raise ValueError("Another package upload is already running")
            # Spool is bounded by content length and container tmpfs; never memory.
            async with upload_lock, temporary_upload() as temporary:
                received = 0
                async for block in request.stream():
                    received += len(block)
                    if received > length:
                        raise ValueError("Upload exceeds its declared length")
                    temporary.write(block)
                if received != length:
                    raise ValueError("Upload is incomplete")
                temporary.seek(0)
                value = await run_in_threadpool(local_request, socket, "POST", "/upload", token=token, stream=temporary, size=length)
        else:
            body = None
            if request.method == "POST":
                if int(request.headers.get("content-length", "0")) > 32768:
                    raise ValueError("Management request is too large")
                raw = bytearray()
                async for block in request.stream():
                    if len(raw) + len(block) > 32768:
                        raise ValueError("Management request is too large")
                    raw.extend(block)
                import json
                body = json.loads(raw or b"{}")
            value = await run_in_threadpool(local_request, socket, request.method, "/" + action, body, token=token)
        response = JSONResponse(value)
        if action == "exchange":
            session = value.pop("token")
            response = JSONResponse(value)
            response.set_cookie(COOKIE, session, httponly=True, secure=os.environ.get("NCT_RECOVERY_INSECURE_TEST") != "1", samesite="strict", max_age=3600)
        return response
    except (ValueError, OSError) as exc:
        return JSONResponse({"detail": str(exc)[:400]}, status_code=409)


from contextlib import asynccontextmanager


@asynccontextmanager
async def temporary_upload():
    with TemporaryFile(dir=os.environ.get("NCT_RECOVERY_SPOOL")) as temporary:
        yield temporary
