"""FastAPI application factory for Lattice v1."""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from lattice.addressing import parse_address
from lattice.messages import CustodyError
from lattice.protocol.constants import (
    MAX_GOSSIP_BATCH_SIZE,
    MAX_GOSSIP_BODY_BYTES,
    MAX_MESSAGE_BODY_BYTES,
    MEDIA_TYPE,
    PROBLEM_CODE_BAD_REQUEST,
    PROBLEM_CODE_FORBIDDEN,
    PROBLEM_CODE_INTERNAL_ERROR,
    PROBLEM_CODE_LENGTH_REQUIRED,
    PROBLEM_CODE_RATE_LIMITED,
    PROBLEM_CODE_SERVICE_UNAVAILABLE,
    PROBLEM_CODE_TOO_LARGE,
    PROBLEM_CODE_UNAUTHORIZED,
    PROBLEM_MEDIA_TYPE,
    PROBLEM_TYPE_BAD_REQUEST,
    PROBLEM_TYPE_FORBIDDEN,
    PROBLEM_TYPE_INTERNAL_ERROR,
    PROBLEM_TYPE_LENGTH_REQUIRED,
    PROBLEM_TYPE_RATE_LIMITED,
    PROBLEM_TYPE_SERVICE_UNAVAILABLE,
    PROBLEM_TYPE_TOO_LARGE,
    PROBLEM_TYPE_UNAUTHORIZED,
    ROUTE_GOSSIP,
    ROUTE_MESSAGES,
    ROUTE_WELL_KNOWN,
)
from lattice.runtime import BlockedSenderError, RuntimeCoordinator


class ProblemDetail(BaseModel):
    """RFC 9457 Problem Details response."""

    type: str = PROBLEM_TYPE_INTERNAL_ERROR
    title: str
    status: int
    detail: str
    code: str = PROBLEM_CODE_INTERNAL_ERROR
    instance: str | None = None


class SubmitRequest(BaseModel):
    """Local submission request body."""

    message_id: str = Field(min_length=1, max_length=128)
    from_address: str = Field(min_length=1, max_length=320)
    to_address: str = Field(min_length=1, max_length=320)
    content: str
    priority: str = "normal"
    ttl_seconds: int | None = None
    extension: dict[str, Any] | None = None


class SubmitResponse(BaseModel):
    """Local submission response body."""

    message_id: str
    status: str


# Maps HTTP status → (type URI, machine-readable code)
_STATUS_PROBLEM_MAP: dict[int, tuple[str, str]] = {
    400: (PROBLEM_TYPE_BAD_REQUEST, PROBLEM_CODE_BAD_REQUEST),
    401: (PROBLEM_TYPE_UNAUTHORIZED, PROBLEM_CODE_UNAUTHORIZED),
    411: (PROBLEM_TYPE_LENGTH_REQUIRED, PROBLEM_CODE_LENGTH_REQUIRED),
    413: (PROBLEM_TYPE_TOO_LARGE, PROBLEM_CODE_TOO_LARGE),
    429: (PROBLEM_TYPE_RATE_LIMITED, PROBLEM_CODE_RATE_LIMITED),
    500: (PROBLEM_TYPE_INTERNAL_ERROR, PROBLEM_CODE_INTERNAL_ERROR),
    503: (PROBLEM_TYPE_SERVICE_UNAVAILABLE, PROBLEM_CODE_SERVICE_UNAVAILABLE),
}
_DEFAULT_TYPE_CODE: tuple[str, str] = (PROBLEM_TYPE_INTERNAL_ERROR, PROBLEM_CODE_INTERNAL_ERROR)


def _problem(
    status: int,
    title: str,
    detail: str,
    instance: str | None = None,
) -> JSONResponse:
    problem_type, problem_code = _STATUS_PROBLEM_MAP.get(status, _DEFAULT_TYPE_CODE)
    body: dict[str, object] = {
        "type": problem_type,
        "title": title,
        "status": status,
        "detail": detail,
        "code": problem_code,
    }
    if instance is not None:
        body["instance"] = instance
    return JSONResponse(
        status_code=status,
        content=body,
        media_type=PROBLEM_MEDIA_TYPE,
    )


def _peer_ip(request: Request) -> str:
    """Best-effort peer identifier for unauthenticated rate limiting.

    Proxy headers are trusted only as far as the checked-in nginx config
    (deploy/lattice.nginx.conf) implies: nginx sets ``X-Real-IP`` itself
    from ``$remote_addr`` and, via ``$proxy_add_x_forwarded_for``, APPENDS
    the real client address after any client-supplied XFF values — so the
    rightmost XFF entry is the proxy-controlled one. There is no configured
    trusted-proxy set; nothing here can see past the front proxy.
    """
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # Rightmost entry: nginx appends $remote_addr AFTER client-supplied
        # values, so the leftmost entries are attacker-chosen and rotating
        # them must not mint fresh rate-limit buckets (9qbf).
        return forwarded.split(",")[-1].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _extract_domain_from_address(address: str) -> str:
    """Extract domain from a ``user@domain`` lattice address."""
    parsed = parse_address(address)
    return parsed.domain if parsed.domain else ""


def create_app(runtime: RuntimeCoordinator) -> FastAPI:
    """Create a stateless FastAPI app wired to ``runtime``."""
    app = FastAPI(
        title="Lattice",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Convert common FastAPI exceptions into RFC 9457 Problem Details.
    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors_list = []
        for e in exc.errors():
            loc_str = ".".join(str(part) for part in e["loc"])
            errors_list.append({"field": loc_str, "message": e["msg"]})
        return JSONResponse(
            status_code=400,
            content={
                "type": PROBLEM_TYPE_BAD_REQUEST,
                "title": "Validation Error",
                "status": 400,
                "detail": str(errors_list),
                "code": PROBLEM_CODE_BAD_REQUEST,
                "instance": str(request.url.path),
            },
            media_type=PROBLEM_MEDIA_TYPE,
        )

    @app.exception_handler(HTTPException)
    async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        title_map = {
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            411: "Length Required",
            413: "Too Large",
            429: "Rate Limited",
            503: "Service Unavailable",
        }
        status = exc.status_code or 500
        title = title_map.get(status, f"HTTP {status}")
        detail = exc.detail if hasattr(exc, "detail") and isinstance(exc.detail, str) else str(exc)
        return _problem(status, title, detail, str(request.url.path))

    # -----------------------------------------------------------------------
    # Dependencies
    # -----------------------------------------------------------------------

    def require_content_length(max_bytes: int) -> Any:
        def checker(request: Request) -> None:
            length = request.headers.get("content-length")
            if length is not None:
                try:
                    if int(length) > max_bytes:
                        raise HTTPException(
                            status_code=413,
                            detail=f"request body exceeds {max_bytes} bytes",
                        )
                except ValueError:
                    raise HTTPException(status_code=400, detail="invalid Content-Length") from None
            else:
                raise HTTPException(status_code=411, detail="Content-Length required")

        return Depends(checker)

    def require_admin(request: Request) -> None:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="admin bearer required")
        token = auth[7:].strip()
        if not secrets.compare_digest(token, runtime.admin_bearer):
            raise HTTPException(status_code=401, detail="invalid admin bearer")

    def require_ready() -> None:
        if not runtime.is_ready():
            raise HTTPException(status_code=503, detail="service not ready")

    # -----------------------------------------------------------------------
    # Health (loopback only in production; blocked by Nginx externally)
    # -----------------------------------------------------------------------

    @app.get("/lattice/v1/health/live")
    def liveness() -> Response:
        return Response(status_code=200)

    @app.get("/lattice/v1/health/ready")
    def readiness() -> Response:
        if runtime.is_ready():
            return Response(status_code=200)
        return Response(status_code=503)

    # -----------------------------------------------------------------------
    # Public federation routes
    # -----------------------------------------------------------------------

    @app.get(ROUTE_WELL_KNOWN, dependencies=[Depends(require_ready)])
    def well_known() -> Response:
        body = runtime.well_known_document
        return JSONResponse(
            content=body,
            media_type=MEDIA_TYPE,
            headers={"Cache-Control": "public, max-age=3600"},
        )

    @app.post(
        ROUTE_GOSSIP,
        dependencies=[
            require_content_length(MAX_GOSSIP_BODY_BYTES),
            Depends(require_ready),
        ],
    )
    def receive_gossip(body: dict[str, Any], request: Request) -> JSONResponse:
        cards = body.get("cards", [])
        if not isinstance(cards, list):
            return _problem(400, "Bad Request", '"cards" must be an array')
        introduced_by = body.get("introduced_by")
        if introduced_by is not None and not isinstance(introduced_by, str):
            return _problem(400, "Bad Request", '"introduced_by" must be a string')
        if len(cards) > MAX_GOSSIP_BATCH_SIZE:
            return _problem(
                400,
                "Batch too large",
                f"gossip batch exceeds {MAX_GOSSIP_BATCH_SIZE} cards",
            )
        # Quota key is the proxy-controlled client address, NOT the
        # self-asserted card identity (bq2m): cards[0] is signed by the
        # root key the card itself advertises, so an attacker can mint
        # unlimited identities — or replay a real peer's card — and each
        # would otherwise get (or drain) a fresh full gossip bucket. Keying
        # on the transport address means the limit actually limits a
        # hostile sender; a third party cannot spend another node's quota.
        peer_id = _peer_ip(request)
        if not runtime.rate_limiter.allow_gossip(peer_id):
            return _problem(429, "Rate limited", "gossip rate limit exceeded")
        results = runtime.gossip_service.receive_batch(cards, introduced_by=introduced_by)
        accepted = sum(1 for r in results if r.accepted)
        rejected = sum(1 for r in results if not r.accepted)
        errors = [
            {"node_id": r.node_id, "reason": r.reason}
            for r in results
            if not r.accepted and r.reason
        ]
        return JSONResponse(
            status_code=200,
            content={"accepted": accepted, "rejected": rejected, "errors": errors},
        )

    @app.post(
        ROUTE_MESSAGES,
        dependencies=[
            require_content_length(MAX_MESSAGE_BODY_BYTES),
            Depends(require_ready),
        ],
    )
    def receive_message(
        message: dict[str, Any],
        request: Request,
    ) -> JSONResponse:
        try:
            from_node_id, cold_sender = runtime.verify_inbound_message(message)
        except BlockedSenderError:
            # Signature-verified message from a blocked node: take no custody
            # and return a final signed rejected receipt (PROTOCOL.md §8).
            receipt = runtime.inbound_service.build_receipt(
                str(message.get("message_id", "")),
                "rejected",
            )
            return JSONResponse(status_code=202, content=receipt)
        except RuntimeError as exc:
            # Malformed/unverifiable message: the body's claimed identity is
            # attacker-chosen here, so the fallback quota is keyed on the
            # proxy-controlled client address, not on from_node_id (eyy7).
            if not runtime.rate_limiter.allow_message(_peer_ip(request)):
                return _problem(429, "Rate limited", "message rate limit exceeded")
            return _problem(401, "Message rejected", str(exc))
        if cold_sender:
            # Unknown sender — IP-keyed rate check AHEAD of queueing the
            # domain for background resolution (the queue itself is bounded
            # in runtime.py); the 503 + Retry-After contract is unchanged.
            # from_node_id is attacker-chosen on this path, so the token is
            # taken from the proxy-controlled client address (eyy7).
            if not runtime.rate_limiter.allow_message(_peer_ip(request)):
                return _problem(429, "Rate limited", "message rate limit exceeded")
            # Queue domain for background resolution and ask the sender to
            # retry. The sender retains its message in its own outbound queue.
            runtime.queue_domain_resolution(from_node_id)
            return JSONResponse(
                status_code=503,
                content={
                    "type": PROBLEM_TYPE_SERVICE_UNAVAILABLE,
                    "title": "Sender unknown",
                    "status": 503,
                    "detail": f"Domain {from_node_id} has not been pinned yet.",
                    "code": PROBLEM_CODE_SERVICE_UNAVAILABLE,
                },
                media_type=PROBLEM_MEDIA_TYPE,
                headers={"Retry-After": "60"},
            )
        # Signature-verified, known sender: consume the identity token BEFORE
        # the ownership check so foreign (403) requests also spend quota; a
        # verified message consumes exactly one identity token (eyy7).
        if not runtime.rate_limiter.allow_message(from_node_id):
            return _problem(429, "Rate limited", "message rate limit exceeded")
        # Verify recipient ownership: refuse custody of messages not
        # addressed to this node (when own_domains is configured).
        to_domain = _extract_domain_from_address(message.get("to_address", ""))
        if to_domain and runtime._own_domains and to_domain not in runtime._own_domains:
            return JSONResponse(
                status_code=403,
                content={
                    "type": PROBLEM_TYPE_FORBIDDEN,
                    "title": "Not this node",
                    "status": 403,
                    "detail": f"Message not addressed to any known local domain ({to_domain})",
                    "code": PROBLEM_CODE_FORBIDDEN,
                },
                media_type=PROBLEM_MEDIA_TYPE,
            )
        try:
            receipt = runtime.inbound_service.accept(message, from_node_id)
        except CustodyError:
            # Durable custody could not be established; final signed rejection.
            rejected = runtime.inbound_service.build_receipt(
                str(message.get("message_id", "")),
                "rejected",
            )
            return JSONResponse(status_code=202, content=rejected)
        except RuntimeError as exc:
            return _problem(400, "Custody rejected", str(exc))
        runtime._audit_inbound_accepted(
            message_id=message.get("message_id", ""),
            from_node_id=from_node_id,
        )
        # Return the signed receipt so sender can validate custody transfer.
        # The receipt contains node_id, message_id, status, etc.
        return JSONResponse(status_code=202, content=receipt)

    # -----------------------------------------------------------------------
    # Local/admin routes
    # -----------------------------------------------------------------------

    @app.get("/lattice/v1/admin/status")
    def admin_status(
        _admin: None = Depends(require_admin),
    ) -> JSONResponse:
        peers = runtime.topology_service._peers.list_all()
        pending = runtime.outbound_service.list_pending()
        return JSONResponse(
            status_code=200,
            content={
                "node_id": runtime.node_id,
                "domain": runtime.config.domain,
                "public_base_url": runtime.config.public_base_url,
                "ready": runtime.is_ready(),
                "running": runtime.is_running,
                "peers": {
                    "total": len(peers),
                    "verified": sum(1 for p in peers if p.state == "verified"),
                    "established": sum(1 for p in peers if p.state == "established"),
                    "blocked": sum(1 for p in peers if p.state == "blocked"),
                },
                "outbound_pending": len(pending),
            },
        )

    @app.post("/lattice/v1/admin/messages/submit")
    def admin_submit(
        req: SubmitRequest,
        _admin: None = Depends(require_admin),
    ) -> JSONResponse:
        if not runtime.allow_submission():
            return _problem(503, "Backpressure", "outbound queue full")
        try:
            _, to_node_id = runtime.resolve_destination(req.to_address)
        except (RuntimeError, ValueError) as exc:
            # Fail closed: resolve_destination also raises ResolutionError and
            # AddressError (both ValueError) for malformed or unresolvable
            # addresses — a RuntimeError-only handler would leak a raw 500.
            return _problem(400, "Address resolution failed", str(exc))
        try:
            ttl = req.ttl_seconds or runtime.config.default_ttl_seconds
            signed = runtime.sign_local_message(
                message_id=req.message_id,
                from_address=req.from_address,
                to_address=req.to_address,
                content=req.content,
                priority=req.priority,
                ttl_seconds=ttl,
                extension=req.extension,
            )
            runtime.outbound_service.submit(signed, to_node_id, ttl_seconds=ttl)
        except (RuntimeError, ValueError) as exc:
            return _problem(400, "Submit failed", str(exc))
        return JSONResponse(
            status_code=202,
            content={"message_id": req.message_id, "status": "accepted"},
        )

    return app
