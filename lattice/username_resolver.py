"""
Username resolution interface for Lattice.

Lattice is a standalone federation protocol that doesn't manage users directly.
External systems (like MIRA) provide a username resolver function to map
usernames to user IDs for message delivery.

Usage by external system:
    from lattice.username_resolver import set_username_resolver

    def my_resolver(username: str) -> Optional[str]:
        # Query your user database
        user = db.query("SELECT id FROM users WHERE username = ?", username)
        return str(user.id) if user else None

    set_username_resolver(my_resolver)
"""

from typing import Callable, Optional

# Global resolver function - set by external system
_username_resolver: Optional[Callable[[str], Optional[str]]] = None


def set_username_resolver(resolver: Callable[[str], Optional[str]]) -> None:
    """
    Set the username resolver function.

    This must be called by the external system before Lattice can
    deliver federated messages to local users.

    Args:
        resolver: Function that takes a username string and returns
                  the user_id (as string) if found, None otherwise.
    """
    global _username_resolver
    _username_resolver = resolver


def resolve_username(username: str) -> Optional[str]:
    """
    Resolve a username to a user_id.

    Args:
        username: The username to resolve (e.g., "taylor")

    Returns:
        User ID (as string) if username exists, None otherwise

    Raises:
        RuntimeError: If no username resolver has been configured
    """
    if _username_resolver is None:
        raise RuntimeError(
            "No username resolver configured. "
            "External systems must call set_username_resolver() before "
            "Lattice can deliver federated messages to local users."
        )
    return _username_resolver(username)


def has_username_resolver() -> bool:
    """Check if a username resolver has been configured."""
    return _username_resolver is not None
