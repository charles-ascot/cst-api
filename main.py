"""Chimera Portal API.

Two responsibilities:

1. Login: validate credentials and mint a short-lived HS256 JWT used by the
   browser to authenticate against this API.
2. Proxy: take authenticated requests from the browser and forward them to
   locked-down Cloud Run services (FSU100, backtest-tool, FSU1E, …),
   attaching a Google IAM ID token for the upstream service. This is the
   single auth boundary between the browser and the rest of the platform —
   FSU services stay deployed with --no-allow-unauthenticated and never
   need their own API keys.
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

import bcrypt
import httpx
import jwt
from dotenv import load_dotenv
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token as google_id_token
from pydantic import BaseModel

load_dotenv()

# ── Config ──────────────────────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "8"))

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@chimerasportstrading.com")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")  # bcrypt hash

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "https://chimerasportstrading.com,https://www.chimerasportstrading.com",
).split(",")


def _parse_proxy_targets() -> dict[str, str]:
    """Parse the ``PROXY_TARGETS`` env var into a name → upstream URL map.

    Format: ``name=https://...,name2=https://...``. Trailing slashes are
    stripped so callers can build URLs by concatenating ``/path``.
    """

    raw = os.getenv("PROXY_TARGETS", "")
    out: dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        name, url = entry.split("=", 1)
        name, url = name.strip(), url.strip().rstrip("/")
        if name and url:
            out[name] = url
    return out


PROXY_TARGETS = _parse_proxy_targets()

PROXY_TIMEOUT_SECONDS = float(os.getenv("PROXY_TIMEOUT_SECONDS", "60"))
ID_TOKEN_CACHE_SECONDS = int(os.getenv("ID_TOKEN_CACHE_SECONDS", str(50 * 60)))

# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Chimera Portal API",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

security = HTTPBearer()


# ── Models ───────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    email: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class ProxyTargetsResponse(BaseModel):
    targets: list[str]


# ── Helpers ──────────────────────────────────────────────────────────────────
def create_token(email: str) -> str:
    payload = {
        "sub": email,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    payload = decode_token(credentials.credentials)
    return payload.get("sub")


# ── ID-token minting ─────────────────────────────────────────────────────────
_id_token_cache: dict[str, tuple[str, float]] = {}
_id_token_lock = asyncio.Lock()


async def _get_id_token(audience: str) -> str:
    """Return a Google IAM ID token for ``audience``, cached per-process.

    On Cloud Run the metadata server resolves an ID token for the runtime
    service account; locally :mod:`google.auth` falls back to ADC. Tokens
    last one hour and are cached just under that to avoid round-trips on
    every proxied request.
    """

    now = time.time()
    cached = _id_token_cache.get(audience)
    if cached and cached[1] > now:
        return cached[0]
    async with _id_token_lock:
        cached = _id_token_cache.get(audience)
        if cached and cached[1] > now:
            return cached[0]
        token = await asyncio.to_thread(
            google_id_token.fetch_id_token, GoogleAuthRequest(), audience
        )
        _id_token_cache[audience] = (token, now + ID_TOKEN_CACHE_SECONDS)
        return token


# ── Header filtering ─────────────────────────────────────────────────────────
_HOP_BY_HOP = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
    }
)


def _filter_request_headers(headers) -> dict[str, str]:
    """Strip hop-by-hop headers and the inbound Authorization."""

    out: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in _HOP_BY_HOP:
            continue
        if lower in {"authorization", "cookie"}:
            # Authorization is replaced with the upstream IAM ID token below;
            # cookies are scoped to the portal-api domain only.
            continue
        out[key] = value
    return out


def _filter_response_headers(headers) -> dict[str, str]:
    """Strip headers that would corrupt the response when relayed."""

    out: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in _HOP_BY_HOP:
            continue
        if lower == "content-encoding":
            # httpx has already decoded the body for us.
            continue
        out[key] = value
    return out


# ── Routes ───────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "chimera-portal-api",
        "proxy_targets": sorted(PROXY_TARGETS.keys()),
    }


@app.post("/api/auth/login", response_model=LoginResponse)
def login(body: LoginRequest):
    email = body.email.strip().lower()

    if email != ADMIN_EMAIL.strip().lower():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    if not ADMIN_PASSWORD_HASH:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auth not configured",
        )

    if not verify_password(body.password, ADMIN_PASSWORD_HASH):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    token = create_token(email)
    return LoginResponse(access_token=token, user=UserOut(email=email))


@app.get("/api/auth/me", response_model=UserOut)
def me(current_user: str = Depends(get_current_user)):
    return UserOut(email=current_user)


@app.get("/api/proxy/_targets", response_model=ProxyTargetsResponse)
def proxy_targets(current_user: str = Depends(get_current_user)):
    """List the proxy targets the portal can route to.

    Useful for the frontend to introspect which FSUs are reachable without
    hard-coding service names.
    """

    return ProxyTargetsResponse(targets=sorted(PROXY_TARGETS.keys()))


@app.api_route(
    "/api/proxy/{service}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy(
    service: str,
    path: str,
    request: Request,
    token: Optional[str] = Query(
        default=None,
        description=(
            "Portal JWT, accepted as a query param so EventSource clients "
            "(which cannot set headers) can authenticate."
        ),
    ),
):
    """Forward an authenticated request to a locked Cloud Run service.

    Accepts the portal JWT either as a Bearer header or as ``?token=`` for
    SSE clients, mints a Google IAM ID token for the upstream audience,
    and relays the request via httpx. Streams the response unchanged for
    Server-Sent Events endpoints.
    """

    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        decode_token(auth_header.split(None, 1)[1])
    elif token:
        decode_token(token)
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing portal credentials",
        )

    upstream_base = PROXY_TARGETS.get(service)
    if not upstream_base:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown proxy target '{service}'",
        )

    upstream_url = f"{upstream_base}/{path}"
    forwarded_pairs = [
        (key, value)
        for key, value in request.query_params.multi_items()
        if key != "token"
    ]
    if forwarded_pairs:
        upstream_url = f"{upstream_url}?{urlencode(forwarded_pairs)}"

    id_tok = await _get_id_token(upstream_base)
    headers = _filter_request_headers(request.headers)
    headers["Authorization"] = f"Bearer {id_tok}"

    body = await request.body()

    is_sse = path.rstrip("/").endswith("admin/events")
    if is_sse:
        client = httpx.AsyncClient(timeout=None)

        async def _stream_upstream():
            try:
                async with client.stream(
                    request.method,
                    upstream_url,
                    headers=headers,
                    content=body,
                ) as upstream:
                    async for chunk in upstream.aiter_raw():
                        yield chunk
            finally:
                await client.aclose()

        return StreamingResponse(_stream_upstream(), media_type="text/event-stream")

    async with httpx.AsyncClient(timeout=PROXY_TIMEOUT_SECONDS) as client:
        upstream = await client.request(
            request.method,
            upstream_url,
            headers=headers,
            content=body,
        )

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_filter_response_headers(upstream.headers),
    )
