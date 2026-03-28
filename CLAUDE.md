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
5. **SECURITY DEFINER Safety**: All definer functions schema-qualify external calls
6. **Effective Role Privilege Checks**: Functions like `rotate()` and `verify()` check
   privileges against the effective role, honoring `SET ROLE` privilege reduction

### Privilege Model for SECURITY DEFINER Functions

When SECURITY DEFINER functions need to check caller privileges:

1. **Do NOT use `current_user`**: Inside SECURITY DEFINER, `current_user` is the function owner
2. **Do NOT use `session_user` alone**: It ignores `SET ROLE` privilege reduction
3. **Use the effective role pattern**:
   ```sql
   v_effective_role NAME := pg_catalog.COALESCE(
       pg_catalog.NULLIF(pg_catalog.NULLIF(pg_catalog.current_setting('role', true), ''), 'none'),
       pg_catalog.session_user()
   );
   ```
   This honors `SET ROLE` if used, otherwise falls back to `session_user`.

4. **Why this matters**:
   - User A does `SET ROLE restricted_role` → expects operations authorized as restricted_role
   - Using `session_user()` alone would check A's privileges, bypassing the restriction
   - The effective role pattern correctly checks restricted_role's privileges

### Security Guidelines for Contributors

When modifying SQL functions:

1. **SECURITY DEFINER functions must use `SET search_path TO pg_catalog`**:
   - This prevents search_path hijacking attacks
   - All object references must be schema-qualified (e.g., `@extschema@.cipher_key_table`,
     `pg_catalog.pg_attribute`)

2. **Use `@extschema@` for extension objects**:
   - The extension uses a fixed `encrypt` schema (`relocatable = false`, `schema = encrypt`)
   - Users must create the schema before installation: `CREATE SCHEMA encrypt;`
   - NEVER hardcode schema names like `encrypt.` in SQL scripts - use `@extschema@`
   - PostgreSQL substitutes `@extschema@` with `encrypt` at install time
   - Examples: `@extschema@.cipher_key_table`, `@extschema@._pgcrypto_schema()`
   - Note: Full relocatability is not supported due to PostgreSQL's `@extschema@`
     substitution limitations with `relocatable = true`

3. **Dynamic pgcrypto schema lookup**:
   - pgcrypto can be installed in any schema, not just `public`
   - Use `@extschema@._pgcrypto_schema()` to get the actual schema at runtime
   - Use dynamic SQL with `format()` and `EXECUTE` for pgcrypto calls:
     ```sql
     v_pgcrypto_schema := @extschema@._pgcrypto_schema();
     EXECUTE format('SELECT %I.pgp_sym_encrypt($1, $2, $3)', v_pgcrypto_schema)
        INTO v_wrapped_key
       USING dek, passphrase, 'cipher-algo=aes256, s2k-mode=3';
     ```

4. **Type name lookups in SECURITY DEFINER context**:
   - When `search_path = pg_catalog`, `format_type()` returns schema-qualified names
   - Use `typname` from `pg_type` for comparisons (e.g., `encrypted_text`)
   - Use schema-qualified names for dynamic SQL casts (lookup from `pg_namespace`)
   - Example: get both values in one query by joining `pg_type` and `pg_namespace`

5. **Dynamic SQL type casts must use quoted identifiers**:
   - When building schema-qualified type names for dynamic SQL, use `format('%I.%I', schema, type)`
   - Never use string concatenation (`schema || '.' || type`) as it breaks with special characters

6. **All pgcrypto function calls must be schema-safe**:
   - This includes `hmac()`, `pgp_sym_encrypt()`, `pgp_sym_decrypt()`, etc.
   - Use `@extschema@._pgcrypto_schema()` helper for schema lookup
   - Use dynamic SQL with `EXECUTE format('%I.function_name(...)', schema)`

7. **Upgrade scripts must maintain security parity with fresh installs**:
   - If a function is redefined in an upgrade script, apply the same security
     patterns as the fresh install script

8. **The `requires = 'pgcrypto'` in `column_encrypt.control` ensures pgcrypto exists**.

9. **Documentation must use actual SQLSTATE codes**:
   - When documenting SQLSTATE, use 5-character codes (e.g., `28P01`)
   - Condition names (e.g., `invalid_password`) may be shown alongside but not instead of codes
   - Reference: https://www.postgresql.org/docs/current/errcodes-appendix.html

10. **SECURITY DEFINER functions must not allow privilege escalation**:
    - Dynamic SQL on user-supplied table/column names must verify caller privileges
    - Use `has_table_privilege(session_user(), table, 'SELECT'/'UPDATE')` before dynamic queries
    - Use `has_column_privilege(session_user(), table, column, 'SELECT'/'UPDATE')` for column access
    - Return error or raise exception if caller lacks required privilege

11. **Avoid duplicate helper logic**:
    - Centralize common patterns (e.g., pgcrypto schema lookup) in internal helper functions
    - All functions go in `@extschema@` - both internal helpers and public API
    - Reference helpers as `@extschema@._pgcrypto_schema()` in SQL scripts
    - Helpers should be STABLE or IMMUTABLE as appropriate for their behavior

12. **Public API functions calling private helpers must use SECURITY DEFINER**:
    - Internal helpers (e.g., `_pgcrypto_schema()`) are revoked from PUBLIC
    - Public API functions granted to `column_encrypt_user` that call these helpers
      will fail with "permission denied" unless they are SECURITY DEFINER
    - All `encrypt.*` API functions should be SECURITY DEFINER with `SET search_path TO pg_catalog`
    - This pattern maintains least privilege while allowing controlled access

13. **Function volatility must match actual behavior**:
    - IMMUTABLE: No catalog lookups, no external state access
    - STABLE: Catalog lookups OK, same result within transaction
    - VOLATILE: External state changes, non-deterministic results

14. **Functions that modify global key state must handle concurrency**:
    - `activate_key()` changes which key is active for all sessions
    - Use `LOCK TABLE ... IN EXCLUSIVE MODE` to serialize concurrent access
    - Without explicit locking, concurrent activations can race and hit unique constraint
    - Prefer deterministic behavior over relying on constraint violation errors

15. **GUC checks with `current_setting(..., true)` must handle NULL**:
    - `current_setting('name', true)` returns NULL if the setting doesn't exist
    - Using `<> 'value'` with NULL yields NULL, not TRUE
    - Use `IS DISTINCT FROM` or `COALESCE(..., 'default')` for correct boolean logic
    - Example: `IF current_setting('encrypt.enable', true) IS DISTINCT FROM 'on'`

### Upgrade Script Rules

1. **Never assume objects exist in a specific schema**:
   - Use `@extschema@` for all extension object references
   - Never hardcode `public.` or `encrypt.` schema names
   - The control file `schema = encrypt` determines the actual schema

2. **DO blocks must use dynamic schema lookup**:
   - Cannot use `@extschema@` inside anonymous DO blocks
   - Look up schema dynamically from `pg_extension`:
     ```sql
     DO $$
     DECLARE
         v_extschema text;
     BEGIN
         SELECT n.nspname INTO v_extschema
           FROM pg_extension e
           JOIN pg_namespace n ON n.oid = e.extnamespace
          WHERE e.extname = 'column_encrypt';
         -- Use format('%I.table_name', v_extschema) for table references
     END;
     $$;
     ```

3. **CI must create the extension schema before v2.0/v3.x installs**:
   - The control file specifies `schema = encrypt`
   - Run `CREATE SCHEMA IF NOT EXISTS encrypt;` before `CREATE EXTENSION`
   - Use schema-qualified function names in `has_function_privilege()` checks

4. **Upgrade scripts must NOT use `CREATE SCHEMA IF NOT EXISTS`**:
   - PostgreSQL's `CREATE SCHEMA IF NOT EXISTS` fails with "schema is not a member of
     extension" when the schema was pre-created externally (not by extension)
   - With `relocatable = false` + `schema = encrypt`, users must pre-create the schema
   - Use conditional DO block instead:
     ```sql
     DO $$
     BEGIN
         IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'encrypt') THEN
             CREATE SCHEMA encrypt;
         END IF;
     END;
     $$;
     ```
   - This handles both upgrade (schema may not exist) and fresh install (user pre-created) scenarios

5. **Upgrade scripts must include the `_pgcrypto_schema()` helper**:
   - If upgrade script creates functions that call pgcrypto, include the helper
   - The helper allows dynamic lookup of pgcrypto's actual schema

6. **All SECURITY DEFINER functions in upgrades must use `pg_catalog` search_path**:
   - Never use `SET search_path TO public` (security vulnerability)
   - Use `SET search_path TO pg_catalog`
   - Schema-qualify all table/function references

### Documentation Rules

1. **Do not document superuser-only GUCs as standard user workflows**:
   - `encrypt.key_version` and `encrypt.enable` are `PGC_SUSET` (superuser-only)
   - Prefer SECURITY DEFINER wrapper functions (e.g., `encrypt.activate_key()`) over direct GUC manipulation
   - If a GUC must be documented, clearly state "requires superuser"

2. **Validate permission model in examples**:
   - Examples should work for users granted `column_encrypt_user` role
   - Do not show operations that require privileges beyond the role grants

3. **Document search_path requirements when showing unqualified type usage**:
   - Extension types (`encrypted_text`, `encrypted_bytea`) live in the `encrypt` schema
   - Unqualified type names require `encrypt` in `search_path`
   - Either show `search_path` setup OR use schema-qualified names (`encrypt.encrypted_text`)
   - CI tests must set `search_path` to match real-world usage patterns

4. **SQL section headers must match actual grants**:
   - If a function is granted to `column_encrypt_user`, do not label it as "internal" or "not exposed"
   - Distinguish between truly internal functions (no grants) and user-accessible helpers
   - Example: `loaded_cipher_key_versions()` is user-accessible for session introspection
   - Keep comments honest to avoid confusion during security reviews

5. **Distinguish SQL upgrade mechanics from operational migration guidance**:
   - PostgreSQL can chain intermediate upgrade scripts automatically (e.g., 3.1→3.3→4.0 in one command)
   - Do NOT write "you cannot upgrade directly from X to Z" when intermediate scripts exist
   - Instead, explain that while technically possible, staged migration is recommended
   - Clearly state WHY staged migration matters (e.g., deprecation period for code updates)
   - Use "we recommend" or "operationally, you should" rather than false technical claims

6. **Document API parameter semantics precisely**:
   - Parameter names like `batch_size` must match actual behavior
   - If a function processes everything in one call with internal chunking, say so
   - Do NOT show example loops that imply per-call incremental behavior when function completes everything
   - Example: `encrypt.rotate(batch_size)` uses batch_size as internal chunk size, not per-call limit
   - Function comments and docs should clearly state "entire column" vs "up to N rows"

### Regression Testing Rules

1. **Security-related behavior must always be regression-tested**:
   - Binary protocol blocking (`col_enc_send_*` raises error)
   - Permission denials for unprivileged users
   - Input validation (DEK length, passphrase requirements)

2. **Do not remove regression coverage without equivalent replacement**:
   - If a comment says "cannot be tested", verify the claim
   - C-level behavior can often be tested via SQL wrapper functions

3. **Test C extension behavior via SQL wrappers when possible**:
   - Type send/receive functions can be called directly
   - Error conditions can be caught in PL/pgSQL exception handlers

4. **Test both encrypted types symmetrically**:
   - `encrypted_text` and `encrypted_bytea` share C implementation
   - Test hash functions (`enc_hash_enctext`, `enc_hash_encbytea`) for both types
   - Test equality operators and hash index support for both types

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
