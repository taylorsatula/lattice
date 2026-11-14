# Lattice database migrations

Lattice uses two SQLite databases.

- **Durable database** (`/var/lib/lattice/lattice.durable.db`) stores pins, identity history, peers, custody, receipts, webhook state, and audit metadata. It survives cache deletion and must be migrated explicitly.
- **Cache database** (`/var/cache/lattice/lattice.cache.db`) stores disposable transient state and is recreated automatically when its schema changes.

## Durable migrations

Durable migrations are cumulative, numbered SQL scripts in `lattice/migrations/durable/`. The runner uses `PRAGMA user_version` to track the applied version and applies every missing migration in order.

Run migrations before starting the daemon:

```bash
sudo lattice upgrade --config /etc/lattice/config.toml
```

The runner:

1. Runs `PRAGMA integrity_check` and `PRAGMA foreign_key_check`.
2. Creates a pre-migration backup in the same directory as the database.
3. Applies each missing migration in a single transaction.
4. Verifies that `PRAGMA user_version` matches the migration number.
5. Refuses to open a database whose `user_version` is newer than the binary.

## Skipped releases

Because migrations are cumulative, upgrading from an older release to the current one applies every intermediate migration in order. There are no skip-version shortcuts.

## Cache migrations

The cache database has no historical migration path. On schema mismatch the cache file is removed and recreated. The cache must contain no irreplaceable state.

## Testing

`tests/test_schema_upgrades.py` verifies:

- Migration from an empty database.
- Rejection of a database newer than the binary.
- Idempotent application of a released schema fixture.
- Pre-migration backup creation.

CI runs this against every released durable schema fixture in `tests/fixtures/durable_schema/`.
