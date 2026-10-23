"""
Integration hooks for the host application (e.g. MIRA).

The discovery daemon runs as its own process on port 1113 and owns all
federation state. The host application's scheduler drives its periodic work
by calling the daemon's admin maintenance endpoints.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import httpx

from .secrets import load_config
from .sqlite_client import SQLiteClient

logger = logging.getLogger(__name__)

DISCOVERY_DAEMON_URL = "http://localhost:1113"

# (job id, endpoint, request body, interval)
SCHEDULED_CALLS = [
    ("lattice_gossip", "/api/v1/announce", {"force": False}, timedelta(minutes=10)),
    ("lattice_message_delivery", "/api/v1/maintenance/process_messages", None, timedelta(minutes=1)),
    ("lattice_neighbor_update", "/api/v1/maintenance/update_neighbors", None, timedelta(hours=6)),
    ("lattice_cleanup", "/api/v1/maintenance/cleanup", None, timedelta(days=1)),
]


def _admin_headers() -> Dict[str, str]:
    token = os.getenv("LATTICE_ADMIN_TOKEN") or os.getenv("ADMIN_TOKEN") or load_config("ADMIN_TOKEN")
    if not token:
        logger.warning("Lattice admin token is not configured; scheduled daemon calls will be rejected")
        return {}
    return {"X-Lattice-Admin-Token": token}


def initialize_lattice_services(scheduler_service) -> bool:
    """Register scheduled calls to the discovery daemon's maintenance endpoints."""
    from apscheduler.triggers.interval import IntervalTrigger

    def make_call(path: str, body: Any):
        def call():
            try:
                response = httpx.post(f"{DISCOVERY_DAEMON_URL}{path}", json=body, headers=_admin_headers(), timeout=30.0)
                if response.status_code != 200:
                    logger.warning("%s returned %d", path, response.status_code)
            except httpx.HTTPError as exc:
                logger.error("Failed to call %s: %s", path, exc)
        return call

    try:
        for job_id, path, body, interval in SCHEDULED_CALLS:
            scheduler_service.register_job(
                job_id=job_id,
                func=make_call(path, body),
                trigger=IntervalTrigger(seconds=interval.total_seconds()),
                component="lattice",
                description=f"Call discovery daemon {path}"
            )
        logger.info("Registered %d lattice scheduler jobs", len(SCHEDULED_CALLS))
        return True
    except Exception as exc:
        logger.error("Failed to initialize lattice services: %s", exc)
        return False


def get_federation_status() -> Dict[str, Any]:
    """Federation identity and peer counts, read directly from the daemon's database."""
    db = SQLiteClient()
    identity = db.execute_single("SELECT server_id, server_uuid, created_at FROM lattice_identity WHERE id = 1")
    if not identity:
        return {"enabled": False, "message": "Federation not initialized"}

    peers = db.execute_single(
        """
        SELECT COUNT(CASE WHEN trust IN ('direct', 'introduced') THEN 1 END) AS total_peers,
               COUNT(CASE WHEN trust = 'direct' THEN 1 END) AS direct_peers,
               COUNT(CASE WHEN trust = 'introduced' THEN 1 END) AS introduced_peers,
               COUNT(CASE WHEN is_neighbor = 1 THEN 1 END) AS neighbors,
               COUNT(CASE WHEN last_seen_at > ? THEN 1 END) AS active_peers
        FROM lattice_peers
        """,
        ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),)
    )
    return {"enabled": True, **identity, "peers": peers, "discovery_daemon_url": DISCOVERY_DAEMON_URL}
