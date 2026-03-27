# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`column_encrypt` is a PostgreSQL extension providing transparent column-level encryption. It uses a two-tier key model (KEK/DEK) where a passphrase wraps data encryption keys stored in the database.

## Build and Test Commands

```bash
# Build
make

# Install (requires sudo for system directories)
sudo make install

# Run regression tests
make installcheck PGDATABASE=test_db

# Clean build artifacts
make clean
```

PostgreSQL must be running with `shared_preload_libraries = 'column_encrypt'` in postgresql.conf.

## Architecture

### Key Components

- **column_encrypt.c** - C extension implementing:
  - `encrypted_text` and `encrypted_bytea` types
  - Type I/O functions with encrypt/decrypt on read/write
  - Session-scoped keyring (process-local memory)
  - Log masking via `emit_log_hook`
  - GUC variables (`encrypt.enable`, `encrypt.key_version`)

- **SQL files** - Extension installation and upgrade scripts:
  - `column_encrypt--4.0.sql` - Clean install (default version)
  - `column_encrypt--3.1--3.3.sql` - Upgrade: adds `encrypt` schema
  - `column_encrypt--3.3--4.0.sql` - Upgrade: removes deprecated functions

### Security Model

1. **KEK (Key Encryption Key)**: User-provided passphrase, never stored
2. **DEK (Data Encryption Key)**: Wrapped with KEK using pgcrypto's `pgp_sym_encrypt`
3. **Session Isolation**: Keys loaded per-connection, cleared on disconnect
4. **Log Protection**: Automatic masking of sensitive function calls

### v4.0 API (encrypt schema)

```sql
-- Key management
encrypt.register_key(dek, passphrase, [activate])  -- Returns key_id
encrypt.load_key(passphrase, [all_versions])       -- Load into session
encrypt.unload_key()                               -- Clear from session
encrypt.activate_key(key_id)                       -- Set for new encryptions
encrypt.revoke_key(key_id)                         -- Prevent loading

-- Operations
encrypt.rotate(schema, table, column, [batch])     -- Re-encrypt data
encrypt.verify(schema, table, column, [sample])    -- Check integrity
encrypt.blind_index(value, hmac_key)               -- Searchable hash

-- Introspection
encrypt.keys()                                     -- List all keys
encrypt.status()                                   -- Quick status check
```

### Version History

- **v4.0**: Clean API with only `encrypt.*` functions, single role
- **v3.3**: Deprecation release introducing `encrypt` schema
- **v3.1**: Production ops features (metrics, coverage audit, rotation jobs)
- **v3.0**: Multi-version key support, batch rotation
- **v2.0**: Three-role security model

## Testing

Tests are in `sql/column_encrypt.sql` with expected output in `expected/column_encrypt.out`.

The test file exercises:
- Role-based access control
- Key registration/loading/unloading
- Encrypted type I/O
- Equality operators and hash functions
- Key rotation workflow
- Error cases

## Files to Understand for Changes

| Area | Files |
|------|-------|
| C internals | `column_encrypt.c` |
| API functions | `column_encrypt--4.0.sql` |
| Upgrade paths | `column_encrypt--X.Y--A.B.sql` |
| Tests | `sql/column_encrypt.sql`, `expected/column_encrypt.out` |
| CI | `.github/workflows/ci.yml` |
