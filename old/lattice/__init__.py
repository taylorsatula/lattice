"""Lattice: DNS-bootstrapped, key-anchored flat mesh for cross-server messaging."""

try:
    from lattice._version import __version__
except ModuleNotFoundError:  # pragma: no cover - generated during wheel builds
    __version__ = "0.0.0+dev"

__all__ = ["__version__"]
