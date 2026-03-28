# GitHub Copilot Instructions for column_encrypt

This repository is a PostgreSQL extension providing transparent column-level
encryption using C and SQL/PGXS. Treat it as security-sensitive systems code.

## Project Overview

- **Version**: 4.0 (simplified API in `encrypt` schema)
- **Extension code**: `column_encrypt.c` (~1000 lines C)
- **SQL API**: `column_encrypt--4.0.sql` (clean install)
- **Upgrade path**: 3.1 → 3.3 (deprecation) → 4.0 (clean)
- **Dependencies**: `pgcrypto`
- **Tested on**: PostgreSQL 14, 15, 16, 17, 18

## v4.0 API (encrypt schema)

```sql
encrypt.register_key(dek, passphrase, [activate])  -- Register key
encrypt.load_key(passphrase, [all_versions])       -- Load into session
encrypt.unload_key()                               -- Clear session
encrypt.activate_key(key_id)                       -- Set active key
encrypt.revoke_key(key_id)                         -- Prevent loading
encrypt.rotate(schema, table, column, [batch])     -- Re-encrypt data
encrypt.verify(schema, table, column, [sample])    -- Check integrity
encrypt.keys()                                     -- List keys
encrypt.status()                                   -- Quick status
encrypt.blind_index(value, hmac_key)               -- Searchable hash
```

## Security Model

- **KEK/DEK model**: Passphrase wraps data encryption key
- **Session-scoped keys**: Keys loaded per-connection, not global
- **Secure cleanup**: `secure_memset` zeros key material
- **Log masking**: `emit_log_hook` masks sensitive function calls
- **Single role**: `column_encrypt_user` for all operations
- **SECURITY DEFINER**: All `encrypt.*` functions run as definer

## Code Review Checklist

### Security (CRITICAL)
- [ ] No plaintext keys in logs, errors, or tests
- [ ] Key buffer handling uses `secure_memset` before free
- [ ] Ciphertext headers validated before use
- [ ] Length checks before varlena/bytea access
- [ ] No insecure fallback behavior
- [ ] `REVOKE FROM PUBLIC` on sensitive functions

### PostgreSQL Extension
- [ ] SQL install script updated if API changes
- [ ] Upgrade script provided for version bumps
- [ ] `column_encrypt.control` version matches scripts
- [ ] PGXS build patterns followed
- [ ] Compatible with PostgreSQL 14+

### Testing
- [ ] Regression tests cover new functionality
- [ ] Error cases tested (wrong passphrase, short key, etc.)
- [ ] Session-scoped behavior verified (keys don't leak between sessions)
- [ ] Upgrade path tested in CI

## Common Patterns

### Key Registration (minimum 16 bytes, recommend 32)
```sql
SELECT encrypt.register_key('my-32-byte-encryption-key-here!', 'passphrase');
```

### Key Loading (session-scoped)
```sql
SELECT encrypt.load_key('passphrase');
-- Now INSERT/SELECT on encrypted columns works in THIS session
```

### Key Rotation
```sql
SELECT encrypt.register_key('new-key-32-bytes-for-aes256!!!', 'pass', false);
SELECT encrypt.load_key('pass', all_versions => true);
SELECT encrypt.activate_key(2);  -- Also sets encrypt.key_version internally
SELECT encrypt.rotate('public', 'table', 'column');
```

## What to Flag in Reviews

1. **Secret leakage**: Keys, passphrases, or decrypted values in logs/errors
2. **Memory safety**: Unchecked lengths, buffer overflows, missing NULL checks
3. **Session confusion**: Assuming keys persist across connections
4. **Upgrade breaks**: Changes to released SQL scripts
5. **Permission issues**: Missing REVOKE or wrong SECURITY DEFINER
6. **Test gaps**: Untested error paths or edge cases

## What NOT to Do

- Store plaintext keys in tables or files
- Log sensitive data "for debugging"
- Assume keys are available across sessions
- Edit released install scripts (use upgrade scripts)
- Weaken validation "for convenience"
- Add PostgreSQL < 14 compatibility hacks

## Review Guidelines for AI Assistants (Copilot, Claude, etc.)

When reviewing this repository, perform **multiple analysis passes** before producing
final recommendations. Do not suggest fixes after a single pass — iterate to find
all related issues and present a consolidated final output.

### Multi-Pass Review Process

1. **Pass 1 — Catalog the issue**: Identify what appears to be wrong
2. **Pass 2 — Verify against implementation**: Read the actual code, not just function signatures
3. **Pass 3 — Check privilege model**: Trace GRANT/REVOKE chains and SECURITY DEFINER usage
4. **Pass 4 — Check CI and install paths**: Verify control file, install scripts, and CI consistency
5. **Pass 5 — Consolidate**: Only then produce recommendations

### Extension Schema and Privilege Model

**Understand before suggesting**:

1. **Internal helpers are intentionally private**:
   - Functions like `_pgcrypto_schema()` are `REVOKE ... FROM PUBLIC` by design
   - Do NOT suggest granting public access to internal helpers
   - If a public function needs a private helper, it should use SECURITY DEFINER

2. **All `encrypt.*` API functions must be SECURITY DEFINER**:
   - This allows them to call internal helpers
   - They must also have `SET search_path TO pg_catalog`
   - If you find a public API function that is NOT SECURITY DEFINER, flag it

3. **Schema ownership follows PostgreSQL extension semantics**:
   - Control file has `schema = encrypt` with `relocatable = false`
   - PostgreSQL creates the schema if it doesn't exist during CREATE EXTENSION
   - Pre-creating the schema externally is allowed but creates ownership nuances
   - Do NOT suggest `CREATE SCHEMA IF NOT EXISTS` inside extension scripts —
     it fails when the schema was pre-created externally

4. **CI must be consistent with install model**:
   - Do NOT suggest CI workarounds without checking `column_encrypt.control`
   - Do NOT suggest schema pre-creation workarounds without understanding why
   - Verify upgrade scripts handle both fresh-install and upgrade scenarios

### Common False Positives to Avoid

| Apparent Issue | Why It May Be Intentional |
|----------------|---------------------------|
| Helper function revoked from PUBLIC | By design — called via SECURITY DEFINER wrappers |
| No explicit schema creation in v4.0.sql | Schema must be pre-created by user/CI before CREATE EXTENSION (see below) |
| Dynamic SQL with `format()` | Required for schema-safe pgcrypto calls |
| `@extschema@` references | Correct pattern for extension schema portability |

### Schema Creation Model

**Important**: With `schema = encrypt` and `relocatable = false` in the control file,
PostgreSQL does **NOT** auto-create the schema. The schema must be pre-created before
`CREATE EXTENSION`. This is why CI jobs include `CREATE SCHEMA IF NOT EXISTS encrypt;`
before installing the extension.

Install scripts (like `column_encrypt--4.0.sql`) do not include `CREATE SCHEMA`
because the schema is expected to already exist.

### PostgreSQL Extension Upgrade Mechanics

**Key fact**: PostgreSQL can automatically chain intermediate upgrade scripts when running
`ALTER EXTENSION ... UPDATE TO 'target'`. For example, with scripts `3.1--3.3.sql` and
`3.3--4.0.sql`, running `ALTER EXTENSION column_encrypt UPDATE TO '4.0'` from v3.1 will
automatically execute both scripts in sequence.

**When reviewing migration/upgrade documentation**:
- Do NOT flag "staged migration" as incorrect just because PostgreSQL can chain scripts
- Staged migration recommendations are **operational guidance**, not technical limitations
- v3.3 is a deprecation release — the intent is for users to stay there and update app code
- The reason to recommend staging is application compatibility, not SQL command capability

**Correct framing**:
- WRONG: "You cannot upgrade directly from 3.1 to 4.0"
- RIGHT: "While PostgreSQL can chain upgrades automatically, we recommend staged migration..."

### Before Suggesting a Fix

Ask yourself:
- Did I read the actual function implementation, not just the signature?
- Did I trace the privilege chain (who can call what)?
- Did I check if this pattern is used consistently elsewhere?
- Did I verify the control file and install script interaction?
- Is this truly a bug, or intentional least-privilege design?

### Output Format for Reviews

Structure findings as:

```
## Issue: [Brief description]

**Status**: Valid / Partially Valid / Not Valid
**Severity**: Critical / High / Medium / Low

**Evidence**: [Specific code references]

**Root Cause**: [Why this happens]

**Recommended Fix**: [Specific change]

**Why This Fix**: [Rationale, alternatives considered]
```

Present all findings together after completing all passes — do not stream
partial findings that may be invalidated by later analysis.

## File Structure

| File | Purpose |
|------|---------|
| `column_encrypt.c` | C extension (types, I/O, hooks, keyring) |
| `column_encrypt--4.0.sql` | v4.0 clean install |
| `column_encrypt--3.3--4.0.sql` | Upgrade: removes deprecated |
| `column_encrypt--3.1--3.3.sql` | Upgrade: adds encrypt schema |
| `sql/column_encrypt.sql` | Regression tests |
| `expected/column_encrypt.out` | Expected test output |

## Commit Message Format

```
<type>: <description>

<body explaining what and why>

Co-Authored-By: <name> <email>
```

Types: `fix`, `feat`, `refactor`, `docs`, `test`, `security`, `build`

---

## Comprehensive Repository Review Prompt

Use this prompt to request a full maintainer-grade assessment:

---

Review this repository end-to-end and produce one consolidated maintainer-grade assessment of column_encrypt.

Do a deep review across:
- extension architecture
- PostgreSQL extension versioning and upgrade scripts
- C code structure and safety
- SQL/PLpgSQL API complexity
- roles and permissions
- key management and encryption assumptions
- tests and CI
- documentation quality
- simplification opportunities

I do not want an incremental review. I want a one-shot review with as many findings as possible.

Please perform multiple internal passes before answering:
- pass 1: architecture and repository layout
- pass 2: security and crypto-related logic
- pass 3: SQL API and extension versioning
- pass 4: tests, CI, and docs
- pass 5: simplification roadmap

Then return a single final report with:
1. Executive summary
2. Most serious risks
3. Biggest complexity hotspots
4. Inconsistencies between code, tests, and docs
5. Concrete simplification recommendations
6. Upgrade/migration concerns
7. Suggested implementation order

Reference specific files and functions wherever possible.
Do not modify code yet.
