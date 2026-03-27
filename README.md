# column_encrypt

[![CI](https://github.com/vibhorkum/column_encrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/vibhorkum/column_encrypt/actions/workflows/ci.yml)
[![License: PostgreSQL](https://img.shields.io/badge/License-PostgreSQL-blue.svg)](LICENSE)
[![Language: PLpgSQL + C](https://img.shields.io/badge/Language-PLpgSQL%20%2B%20C-informational.svg)](#architecture)
[![PostgreSQL: 14-18](https://img.shields.io/badge/PostgreSQL-14--18-336791.svg)](https://www.postgresql.org/)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Architecture](#architecture)
- [Installation](#installation)
- [Docker Regression Testing](#docker-regression-testing)
- [Configuration](#configuration)
- [Usage](#usage)
- [Functions Reference](#functions-reference)
- [GUC Parameters](#guc-parameters)
- [Security Model](#security-model)
- [Key Rotation](#key-rotation)
- [Supported Algorithms](#supported-algorithms)
- [License](#license)

---

## Overview

`column_encrypt` is a PostgreSQL extension that provides **transparent column-level encryption**. It allows database users to use their own keys when inserting data into a table so that data is stored encrypted in designated columns. Users who hold the correct key can read and write encrypted columns without any modification to their SQL queries — encryption and decryption happen transparently at the type input/output level.

---

## Features

- Two custom encrypted data types: **`ENCRYPTED_TEXT`** and **`ENCRYPTED_BYTEA`**
- **Two-tier key model**: Key Encryption Key (KEK) wraps the Data Encryption Key (DEK), so the DEK is never stored in plaintext
- **AES encryption** via the `pgcrypto` extension
- **Key version header** embedded in every ciphertext for future key rotation tracking
- **Version-aware decryption** using the ciphertext header and session-loaded keys
- **Single-role security model** with unified `column_encrypt_user` role
- **Automatic log masking** for sensitive key operations (defense-in-depth)
- **Key registry metadata** with explicit `pending`, `active`, `retired`, and `revoked` states
- **Key rotation** support with both full-table and batched re-encryption helpers
- **Optional blind-index helpers** for scalable equality lookup patterns
- **Hash/equality semantics on decrypted plaintext** so comparisons remain correct across key rotation
- **Session introspection helper** to show which key versions are currently loaded in the backend
- **Cast support** from `bool`, `inet`, `cidr`, `xml`, and `character` to `encrypted_text`

---

## Requirements

- **PostgreSQL 14 or later** (tested with PostgreSQL 14, 15, 16, 17, and 18)
- **`pgcrypto`** extension (listed as a dependency in `column_encrypt.control` and auto-installed if not already present)
- A **C compiler** and **PostgreSQL development headers** (`postgresql-devel` on RPM-based systems, `libpq-dev` / `postgresql-server-dev-*` on Debian/Ubuntu)

---

## Architecture

The extension registers two custom base types (`encrypted_text`, `encrypted_bytea`) backed by variable-length `bytea` storage.

- **On `INSERT`/`UPDATE`**: the type input function (`col_enc_text_in` / `col_enc_bytea_in`) transparently encrypts the supplied plaintext value using the session's currently loaded DEK.
- **On `SELECT`**: the type output function (`col_enc_text_out` / `col_enc_bytea_out`) transparently decrypts the stored ciphertext using the matching session-loaded key for that ciphertext version.
- A **2-byte key version header** is prepended to every ciphertext and used during decryption and re-encryption workflows. The header uses an unambiguous format: bit 15 (0x8000) is set as a flag, with the key version (1-32767) stored in the low 15 bits in network byte order. This ensures cross-platform compatibility and eliminates ambiguity when reading ciphertext. Legacy data written before this format is auto-detected and handled via fallback logic.
- Keys are held in **`TopMemoryContext`** as a versioned in-memory keyring and are securely zeroed with `secure_memset` when removed from session memory.
- An **`emit_log_hook`** masks known sensitive key-management function calls in log messages (query text, detail, context, internal query) to reduce accidental key leakage.
- Administrative and runtime functions are gated by dedicated extension roles instead of `PUBLIC` execution.
- Binary protocol `SEND` / `RECEIVE` is intentionally rejected so clients cannot bypass the text I/O encryption path.
- Equality and hash behavior are defined on **decrypted plaintext**, not raw ciphertext bytes.
- Range ordering on encrypted values is intentionally **unsupported**; use companion blind indexes for scalable equality lookups instead.
- Because equality/hash behavior depends on decrypted plaintext and session key availability, blind-index columns are the recommended pattern for indexed equality at scale.
- When upgrading from releases that used ciphertext-based hash semantics, rebuild any existing hash indexes on encrypted columns before relying on them again.

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/vibhorkum/column_encrypt.git
   cd column_encrypt
   ```

2. **Ensure `pg_config` is in `PATH`:**
   ```bash
   export PATH=/usr/pgsql-<version>/bin:$PATH
   ```

3. **Build and install:**
   ```bash
   make
   make install
   ```

4. **Add the extension to `shared_preload_libraries`** in `postgresql.conf`:
   ```
   shared_preload_libraries = '$libdir/column_encrypt'
   ```

5. **Restart PostgreSQL:**
   ```bash
   pg_ctl restart -D $PGDATA
   # or
   systemctl restart postgresql
   ```

6. **Create the extension** in the target database (requires superuser). `pgcrypto` will be installed automatically as a dependency if it is not already present:
   ```sql
   CREATE EXTENSION column_encrypt;
   ```

### Upgrade Notes

**Upgrading to v4.0:**

v4.0 removes all deprecated functions. You must migrate through v3.3 first:

```sql
-- Step 1: Upgrade to v3.3 (deprecation release)
ALTER EXTENSION column_encrypt UPDATE TO '3.3';

-- Step 2: Update your code to use encrypt.* API (see MIGRATION.md)

-- Step 3: Upgrade to v4.0
ALTER EXTENSION column_encrypt UPDATE TO '4.0';
```

See [MIGRATION.md](MIGRATION.md) for the complete migration guide.

**General notes:**

- After upgrading from v2.x, rebuild any existing hash indexes on `encrypted_text` or `encrypted_bytea` columns.
- For scalable equality lookups, prefer a companion blind-index column instead of direct encrypted-column hash indexing.

---

## Docker Regression Testing

If you do not want to install PostgreSQL development packages on your host, you can build and run the extension tests in Docker instead.

Run the local regression harness against PostgreSQL 18:

```bash
./run-docker-regression.sh
```

Run against a specific supported version (14, 15, 16, 17, or 18):

```bash
./run-docker-regression.sh 14
./run-docker-regression.sh 15
./run-docker-regression.sh 16
./run-docker-regression.sh 17
./run-docker-regression.sh 18
```

What the Docker harness does:

- builds a throwaway Ubuntu-based test image
- installs PostgreSQL server, contrib, and dev packages for the selected version
- runs `make` and `make install`
- initializes a temporary cluster with `shared_preload_libraries = 'column_encrypt'`
- creates a test database and runs `make installcheck`

Files involved:

- `docker/Dockerfile`
- `docker/run-regression.sh`
- `docker/docker-compose.test.yml`
- `run-docker-regression.sh`

This path mirrors the GitHub Actions CI workflow closely, which makes local failures easier to compare with CI results.

---

## Configuration

After installation, the following GUC parameters are available (see [GUC Parameters](#guc-parameters) for full details):

| Parameter | Default | Description |
|---|---|---|
| `encrypt.enable` | `on` | Enable/disable column encryption (superuser only) |
| `encrypt.mask_key_log` | `on` | Mask known sensitive key-management calls in PostgreSQL logs (superuser only) |
| `encrypt.mask_query_literals` | `off` | Mask string literals in PostgreSQL log messages (superuser only) |
| `encrypt.key_version` | `1` | Key version written into ciphertext header (superuser only) |

---

## Usage

### Step 1 — Register the encryption key

Connect as a user with `column_encrypt_user` role and register your Data Encryption Key (DEK) wrapped by a master passphrase (KEK). Log masking is automatic:

```sql
-- Log masking is automatic, no ceremony needed
SELECT encrypt.register_key('my-secret-data-key', 'my-master-passphrase');
```

### Step 2 — Load the key in your session

In each new session, load the DEK into session memory before accessing encrypted columns:

```sql
SELECT encrypt.load_key('my-master-passphrase');
```

### Step 3 — Create a table with encrypted columns and insert data

```sql
CREATE TABLE secure_data(id SERIAL, ssn ENCRYPTED_TEXT);
INSERT INTO secure_data(ssn) VALUES('888-999-2045');
INSERT INTO secure_data(ssn) VALUES('888-999-2046');
INSERT INTO secure_data(ssn) VALUES('888-999-2047');
```

### Step 4 — Read data transparently (key loaded)

```sql
test=# SELECT * FROM secure_data;
 id |     ssn
----+--------------
  1 | 888-999-2045
  2 | 888-999-2046
  3 | 888-999-2047
(3 rows)
```

### Step 5 — Read data without the key (new session, no key loaded)

```sql
test=# SELECT * FROM secure_data;
ERROR:  cannot decrypt data, because key was not set
```

This is the expected result — without loading the key, the ciphertext cannot be decrypted.

### Step 6 — Attempt to load a wrong key

```sql
test=# SELECT encrypt.load_key('wrong-passphrase');
ERROR:  incorrect passphrase
```

This is also expected — an incorrect passphrase is rejected (SQLSTATE `28P01`).

---

## Functions Reference (v4.0 API)

All encryption functions are in the `encrypt` schema:

| Function | Returns | Description |
|---|---|---|
| `encrypt.register_key(dek text, passphrase text, activate boolean DEFAULT true)` | `integer` | Wraps the DEK with the passphrase using AES-256/S2K and stores it. Returns the assigned key_id. |
| `encrypt.load_key(passphrase text, all_versions boolean DEFAULT false)` | `boolean` | Loads key(s) into session memory. Use `all_versions => true` during rotation. |
| `encrypt.unload_key()` | `void` | Securely removes all loaded keys from session memory. |
| `encrypt.activate_key(key_id integer)` | `boolean` | Sets a key as active for new encryptions (retires previous active key). |
| `encrypt.revoke_key(key_id integer)` | `boolean` | Prevents a key from being loaded. |
| `encrypt.rotate(schema text, table text, column text, batch_size integer DEFAULT 10000)` | `bigint` | Re-encrypts data with the active key. Returns rows processed. |
| `encrypt.verify(schema text, table text, column text, sample_size integer DEFAULT 100)` | `setof record` | Verifies encryption integrity by sampling rows. |
| `encrypt.keys()` | `setof record` | Lists all registered keys with state and metadata. |
| `encrypt.status()` | `record` | Returns quick status: key_loaded, active_key_version, encrypted_column_count. |
| `encrypt.blind_index(value text, hmac_key text)` | `text` | Returns a SHA-256 HMAC blind index for searchable lookups. |
| `loaded_cipher_key_versions()` | `integer[]` | Returns key versions currently loaded in session (metadata only). |

---

## GUC Parameters

All parameters require **superuser** (`PGC_SUSET`) to change.

| Parameter | Type | Default | Range | Description |
|---|---|---|---|---|
| `encrypt.enable` | `bool` | `on` | — | Enables or disables column encryption globally. This is independent from the log masking helper functions. |
| `encrypt.mask_key_log` | `bool` | `on` | — | When enabled, masks known sensitive key-management function calls, including case-variant and schema-qualified forms, in PostgreSQL log messages as a defense-in-depth control. |
| `encrypt.mask_query_literals` | `bool` | `off` | — | When enabled, masks string literals in PostgreSQL log messages including single-quoted (`'value'` → `'***'`), empty-tag dollar-quoted (`$$value$$` → `$$***$$`), and tagged dollar-quoted (`$tag$value$tag$` → `$tag$***$tag$`) strings. Useful for environments where query logs must not contain any sensitive data. |
| `encrypt.key_version` | `int` | `1` | `1–32767` | Key version number written into the 2-byte ciphertext header. Increment this when rotating keys to track which version encrypted each value. |

---

## Security Model

- **`cipher_key_table`** stores versioned wrapped keys, activation metadata, and timestamps. Direct table access is revoked from `PUBLIC`.
- All `encrypt.*` functions use **`SECURITY DEFINER`** and are revoked from `PUBLIC`.
- **`column_encrypt_user`** is the single role for all encryption operations (key management, loading, rotation).
- **`encrypt.enable`** is `PGC_SUSET` — only superusers can enable or disable encryption. This prevents unprivileged users from bypassing encryption by toggling the GUC.
- Encryption keys stored in C session memory are **zeroed with `secure_memset`** when removed, preventing key material from lingering in process memory.
- The **`emit_log_hook`** automatically masks known sensitive key-management function calls in PostgreSQL logs. This is a defense-in-depth measure, not a substitute for cautious operational handling of passphrases.
- `loaded_cipher_key_versions()` reveals version metadata only, not DEKs or passphrases.

Example grants:

```sql
-- Grant encryption privileges to application roles
GRANT column_encrypt_user TO app_user;
GRANT column_encrypt_user TO key_manager;
```

### Key Encryption Key (KEK) vs Data Encryption Key (DEK)

| Key | Role | Storage |
|---|---|---|
| **Data Encryption Key (DEK)** | Encrypts/decrypts column data | Stored wrapped (encrypted) in `cipher_key_table`; loaded into session memory on `encrypt.load_key()` |
| **Key Encryption Key (KEK) / Master Passphrase** | Wraps the DEK before storage | Never stored in the database; managed externally |

`encrypt.register_key()` encrypts the DEK with the passphrase using **AES-256 with iterated-salted S2K** (`cipher-algo=aes256, s2k-mode=3`) via `pgcrypto`'s `pgp_sym_encrypt`. `encrypt.load_key()` reverses this with `pgp_sym_decrypt`.

---

## Key Rotation

To rotate the encryption key, follow these steps:

```sql
-- Step 1: Register a new key version (inactive by default)
SELECT encrypt.register_key('new-data-key', 'my-master-passphrase', false);

-- Step 2: Load all key versions for rotation
SELECT encrypt.load_key('my-master-passphrase', all_versions => true);

-- Step 3: Activate the new version and re-encrypt
-- (activate_key sets encrypt.key_version internally)
SELECT encrypt.activate_key(2);
SELECT encrypt.rotate('public', 'secure_data', 'ssn');

-- Or rotate in batches for large tables
DO $$
DECLARE moved bigint;
BEGIN
    LOOP
        moved := encrypt.rotate('public', 'secure_data', 'ssn', 5000);
        EXIT WHEN moved = 0;
    END LOOP;
END;
$$;

-- Step 4: Clear the session keyring
SELECT encrypt.unload_key();
```

After rotation, all new sessions must call `encrypt.load_key('my-master-passphrase')` to use the active key version.

---

## Logical Replication

`column_encrypt` replicates ciphertext, not plaintext. That means:

- subscribers must have the extension installed
- subscribers must manage and load keys independently
- wrapped keys in `cipher_key_table` are not replicated as usable session keys
- replication/apply roles should run with `encrypt.enable = off` so replication transports ciphertext rather than decrypted plaintext

For local end-to-end testing, use the Docker-based logical replication harness to exercise publisher/subscriber behavior.

## Blind Indexing

For scalable equality lookups, prefer a companion blind-index column over direct comparisons on encrypted columns.
Do not rely on `<`, `<=`, `>`, or `>=` semantics for encrypted values; plaintext range ordering is intentionally unsupported.

Example:

```sql
ALTER TABLE secure_data ADD COLUMN ssn_blind_index text;

UPDATE secure_data
SET ssn_blind_index = encrypt.blind_index('888-999-2045', 'blind-index-secret');
```

The blind-index key should be managed separately from the DEK/KEK used for encryption.

---

## Logical Replication: Docker Harness

See [Logical Replication](#logical-replication) above for the conceptual model; this section documents the Docker-based integration harness that validates it end to end.

Recommended pattern:

- Use a dedicated publisher-side replication user with `ALTER ROLE ... SET encrypt.enable = off` so logical decoding emits raw ciphertext instead of decrypted plaintext.
- Use a dedicated subscriber-side subscription owner/apply-worker role with `ALTER ROLE ... SET encrypt.enable = off` so replicated ciphertext is stored directly without requiring a backend-local loaded key.
- Keep normal application sessions on the default `encrypt.enable = on` path and load keys only in roles that were explicitly granted `column_encrypt_user`.
- Load the key only in interactive/application sessions that need to read decrypted values; replication workers should replicate ciphertext, not plaintext.

Run the local integration harness:

```bash
./run-docker-logical-replication.sh 18
```

Files involved:

- `docker/docker-compose.replication.yml`
- `docker/run-logical-replication.sh`
- `run-docker-logical-replication.sh`

## Supported Algorithms

The extension uses AES encryption via `pgcrypto`.

| Algorithm | Description |
|---|---|
| AES-256 | Advanced Encryption Standard with 256-bit key |

The DEK is wrapped using AES-256/S2K (iterated-salted string-to-key) via `pgp_sym_encrypt`.

---

## Error Messages (v4.0)

The v4.0 API uses standard PostgreSQL error messages with SQLSTATE codes:

| SQLSTATE | Condition Name | Message | Cause |
|---|---|---|---|
| `22023` | `invalid_parameter_value` | encryption key cannot be null or empty | DEK is NULL or empty |
| `22023` | `invalid_parameter_value` | encryption key must be at least 16 bytes | DEK is too short (use 32 bytes for AES-256) |
| `22023` | `invalid_parameter_value` | passphrase cannot be null or empty | Passphrase is NULL or empty |
| `28P01` | `invalid_password` | incorrect passphrase | Master passphrase failed to decrypt wrapped key |
| `28P01` | `invalid_password` | failed to decrypt key version N | Passphrase incorrect for specific key version |
| `42602` | `invalid_name` | invalid identifier | Schema/table/column name contains invalid characters |
| `42703` | `undefined_column` | column not found | Target column does not exist |
| `42809` | `wrong_object_type` | not an encrypted column | Target is not `encrypted_text` or `encrypted_bytea` |
| `0A000` | `feature_not_supported` | encryption must be enabled | Operation attempted with `encrypt.enable = off` |
| `22000` | `data_exception` | cannot activate expired key | Key's `expires_at` is in the past |
| `54000` | `program_limit_exceeded` | maximum key version (32767) exceeded | Key version exceeds ciphertext header limit |

**Note**: Legacy error codes (`EDB-ENC*`) from the C layer may still appear for type I/O errors (e.g., "cannot decrypt data, because key was not set").

---

## License

This extension is licensed under the [PostgreSQL License](LICENSE), a permissive open-source license similar to the BSD 2-Clause license.
