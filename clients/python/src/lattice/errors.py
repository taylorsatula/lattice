"""Errors raised by the Lattice client."""

from __future__ import annotations


class LatticeError(Exception):
    """Base class for all lattice client errors."""


class ConnectionError_(LatticeError):
    """The daemon closed the connection or sent an undecodable frame."""


class Rejected(LatticeError):
    """The daemon rejected the request with an error code."""

    def __init__(self, code: int):
        self.code = code
        super().__init__(f"request rejected with error code {code}")


class BadResponse(LatticeError):
    """The daemon sent a response that does not match the protocol."""


class Timeout(LatticeError):
    """A read from the daemon timed out."""


# Error codes from the local API wire contract.
ERR_UNKNOWN_OP = 1
ERR_BAD_ARGS = 2
ERR_AUTH = 3
ERR_NOT_FOUND = 4
ERR_FAILED = 5
