"""Lattice local-API client for Python.

The package is the local-API client only: it speaks to a running
``latticed`` over its Unix sockets. Object verification (KEL, record and
message checks) is not part of the package; it lives in the test suite
(``tests/objects.py``) and is not a supported public API.

See README.md for a tour and the hook-in guide.
"""

from .client import (
    EVENT_INBOX,
    EVENT_STATUS,
    MSG_STATUS_DELIVERED,
    MSG_STATUS_FAILED,
    MSG_STATUS_EXPIRED,
    MSG_STATUS_IN_TRANSIT,
    MSG_STATUS_QUEUED,
    ROUTE_DEFAULT,
    ROUTE_DIRECT,
    ROUTE_WAYPOINT,
    Client,
    Delivery,
    Event,
    Lookup,
    NodeInfo,
)
from .errors import (
    BadResponse,
    ConnectionError_,
    LatticeError,
    Rejected,
    Timeout,
)

__version__ = "0.1.0"

__all__ = [
    "Client",
    "Delivery",
    "Event",
    "Lookup",
    "NodeInfo",
    "LatticeError",
    "ConnectionError_",
    "Rejected",
    "BadResponse",
    "Timeout",
    "EVENT_INBOX",
    "EVENT_STATUS",
    "MSG_STATUS_QUEUED",
    "MSG_STATUS_IN_TRANSIT",
    "MSG_STATUS_DELIVERED",
    "MSG_STATUS_FAILED",
    "MSG_STATUS_EXPIRED",
    "ROUTE_DEFAULT",
    "ROUTE_WAYPOINT",
    "ROUTE_DIRECT",
]
