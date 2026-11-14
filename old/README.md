# Lattice

DNS-bootstrapped, key-anchored flat mesh for cross-server messaging.

## Status

This is an early rewrite (v1). There is no compatibility with the previous pre-release implementation.

## Quick start

Install into a virtual environment:

```bash
python3 -m venv /opt/lattice/venv
/opt/lattice/venv/bin/pip install lattice-mesh
```

Initialize a node:

```bash
sudo /opt/lattice/venv/bin/lattice init \
  --config /etc/lattice/config.toml \
  --domain example.com \
  --public-base-url https://example.com
```

Encrypt the generated credentials with `systemd-creds` (systemd 250+), run migrations, and start the daemon. See `docs/LATTICE_SYSTEMD.md` for the full production deployment guide.

## Development

```bash
uv sync --all-extras
uv run pytest tests/test_*.py -q
uv run ruff check lattice tests
uv run mypy --strict lattice tests
uv build
```

## Documentation

- `docs/PROTOCOL.md` — wire protocol, addressing, and signatures
- `docs/THREAT_MODEL.md` — security assumptions and trust boundaries
- `docs/LATTICE_SYSTEMD.md` — production deployment with systemd and Nginx
- `docs/KEY_MANAGEMENT.md` — root and operational key lifecycle
- `docs/ADDRESSING.md` — `user@domain` and `user@lat_…` usage
- `docs/LOOSE_ENDS.md` — known non-blocking follow-ups

## License

MIT
