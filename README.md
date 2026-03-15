# column_encrypt

[![License: PostgreSQL](https://img.shields.io/badge/License-PostgreSQL-blue.svg)](LICENSE)
[![Language: PLpgSQL + C](https://img.shields.io/badge/Language-PLpgSQL%20%2B%20C-informational.svg)](#architecture)

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
- **Tighter log masking** focused on known sensitive function calls rather than all parenthesized log text
- **Role-based execution model** with dedicated admin, runtime, and reader roles
- **Key registry metadata** with explicit `pending`, `active`, `retired`, and `revoked` states
- **Key rotation** support with both full-table and batched re-encryption helpers
- **Optional blind-index helpers** for scalable equality lookup patterns
- **Hash/equality semantics on decrypted plaintext** so comparisons remain correct across key rotation
- **Session introspection helper** to show which key versions are currently loaded in the backend
- **Cast support** from `bool`, `inet`, `cidr`, `xml`, and `character` to `encrypted_text`
- **Logical replication readiness check** for encrypted tables

---

## Requirements

- **PostgreSQL** (built with standard PGXS; compatible with PostgreSQL 10 and later)
- **`pgcrypto`** extension (listed as a dependency in `column_encrypt.control` and auto-installed if not already present)
- A **C compiler** and **PostgreSQL development headers** (`postgresql-devel` on RPM-based systems, `libpq-dev` / `postgresql-server-dev-*` on Debian/Ubuntu)

---

## Architecture

The extension registers two custom base types (`encrypted_text`, `encrypted_bytea`) backed by variable-length `bytea` storage.

- **On `INSERT`/`UPDATE`**: the type input function (`col_enc_text_in` / `col_enc_bytea_in`) transparently encrypts the supplied plaintext value using the session's currently loaded DEK.
- **On `SELECT`**: the type output function (`col_enc_text_out` / `col_enc_bytea_out`) transparently decrypts the stored ciphertext using the matching session-loaded key for that ciphertext version.
- A **2-byte key version header** is prepended to every ciphertext and used during decryption and re-encryption workflows.
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

- `3.0` changes equality and hash semantics to operate on decrypted plaintext instead of raw ciphertext bytes.
- After `ALTER EXTENSION column_encrypt UPDATE TO '3.0'`, rebuild any existing hash indexes on `encrypted_text` or `encrypted_bytea` columns with `REINDEX` or by dropping and recreating them.
- For scalable equality lookups or uniqueness checks, prefer a companion blind-index column instead of direct encrypted-column hash indexing.
- This is especially important when `encrypt.enable = off` is used in logical replication or apply workflows, because blind indexes avoid dependence on session key availability.

---

## Docker Regression Testing

If you do not want to install PostgreSQL development packages on your host, you can build and run the extension tests in Docker instead.

Run the local regression harness against PostgreSQL 18:

```bash
./run-docker-regression.sh
```

Run against a specific supported version:

```bash
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
| `encrypt.mask_key_log` | `on` | Mask key material in PostgreSQL logs (superuser only) |
| `encrypt.key_version` | `1` | Key version written into ciphertext header (superuser only) |

---

## Usage

### Step 1 — Register the encryption key

Connect as a superuser and register your Data Encryption Key (DEK) wrapped by a master passphrase (KEK). Disable query logging first to prevent the passphrase from appearing in logs:

> **Note:** `'my-secret-data-key'` is an **example key value** (not an algorithm name). The second argument `'aes'` specifies the encryption algorithm.

```sql
SELECT cipher_key_disable_log();
SELECT register_cipher_key('my-secret-data-key', 'aes', 'my-master-passphrase');
SELECT cipher_key_enable_log();
```

### Step 2 — Load the key in your session

In each new session, load the DEK into session memory before accessing encrypted columns. Only roles granted `column_encrypt_runtime` should be allowed to do this. Always call `cipher_key_disable_log()` first to prevent the passphrase from appearing in logs:

```sql
SELECT cipher_key_disable_log();
SELECT load_key('my-master-passphrase');
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
test=# SELECT cipher_key_disable_log();
 cipher_key_disable_log
------------------------
 t
(1 row)

test=# SELECT load_key('wrong-passphrase');
ERROR:  EDB-ENC0012 cipher key is not correct
```

This is also expected — an incorrect passphrase is rejected.

---

## Functions Reference

| Function | Returns | Description |
|---|---|---|
| `register_cipher_key(data_key text, algorithm text, master_passphrase text)` | `integer` | Wraps the DEK with the KEK (master passphrase) using AES-256/S2K and stores it in `cipher_key_table`. |
| `load_key(master_passphrase text)` | `boolean` | Decrypts the active DEK from `cipher_key_table` using the master passphrase and loads it into session memory. |
| `load_key_by_version(master_passphrase text, key_version integer)` | `boolean` | Loads a specific stored key version into the session keyring. |
| `loaded_cipher_key_versions()` | `integer[]` | Returns the key versions currently loaded into the backend session keyring, without exposing key material. |
| `cipher_key_disable_log()` | `boolean` | Disables `track_activities` before sensitive key operations. |
| `cipher_key_enable_log()` | `boolean` | Re-enables `track_activities` after sensitive key operations. |
| `enc_store_key(key text, algorithm text)` | `boolean` | Low-level helper that stores a DEK in session memory under the current `encrypt.key_version`. |
| `enc_store_prv_key(key text, algorithm text)` | `boolean` | Deprecated compatibility alias for `enc_store_key(...)`; it no longer stores a distinct “previous” version. |
| `enc_rm_key()` | `boolean` | Securely removes all loaded DEKs from session memory (zeroes the key bytes). |
| `enc_rm_prv_key()` | `boolean` | Compatibility alias for clearing the loaded keyring. |
| `cipher_key_reencrypt_data(schema text, table text, column text)` | `bigint` | Re-encrypts all values in the specified encrypted column by decrypting with the ciphertext header version and re-encrypting with the current `encrypt.key_version`. Returns the number of rows re-encrypted. |
| `cipher_key_reencrypt_data_batch(schema text, table text, column text, batch_size integer)` | `bigint` | Re-encrypts a bounded batch of rows at a time so callers can rotate large tables incrementally. |
| `activate_cipher_key(key_version integer)` | `boolean` | Marks one registered key version as active and retires the previously active version. |
| `revoke_cipher_key(key_version integer)` | `boolean` | Marks a stored key version as revoked so it can no longer be loaded. |
| `cipher_key_versions()` | `setof record` | Lists registered key versions and their metadata. |
| `column_encrypt_blind_index_text(plaintext text, blind_index_key text)` | `text` | Returns a SHA-256 HMAC blind index for companion lookup columns. |
| `column_encrypt_blind_index_bytea(plaintext bytea, blind_index_key text)` | `text` | Returns a SHA-256 HMAC blind index for binary payloads. |
| `cipher_key_logical_replication_check(schema text, table text)` | `setof record` | Returns local readiness checks and warnings for logical replication of encrypted tables. |

---

## GUC Parameters

All parameters require **superuser** (`PGC_SUSET`) to change.

| Parameter | Type | Default | Range | Description |
|---|---|---|---|---|
| `encrypt.enable` | `bool` | `on` | — | Enables or disables column encryption globally. This is independent from the log masking helper functions. |
| `encrypt.mask_key_log` | `bool` | `on` | — | When enabled, masks known sensitive key-management function calls in PostgreSQL log messages as a defense-in-depth control. |
| `encrypt.key_version` | `int` | `1` | `1–32767` | Key version number written into the 2-byte ciphertext header. Increment this when rotating keys to track which version encrypted each value. |

---

## Security Model

- **`cipher_key_table`** stores versioned wrapped keys, activation metadata, and timestamps. Direct table access is revoked from `PUBLIC`.
- Administrative key operations use **`SECURITY DEFINER`**, but execution is no longer granted to `PUBLIC`.
- `column_encrypt_admin` owns registration, activation, revocation, re-encryption, and operational logging controls.
- `column_encrypt_runtime` is intended for application roles that are allowed to load keys and clear their session keyring. If you want to prevent most application roles from loading keys, do not grant this role broadly.
- `column_encrypt_reader` is intended for read-only metadata and replication-readiness inspection.
- **`encrypt.enable`** is `PGC_SUSET` — only superusers can enable or disable encryption. This prevents unprivileged users from bypassing encryption by toggling the GUC.
- Low-level helper functions such as `enc_store_key`, `enc_store_prv_key`, and `pgstat_actv_mask` are revoked from `PUBLIC`.
- Encryption keys stored in C session memory are **zeroed with `secure_memset`** when removed, preventing key material from lingering in process memory.
- The **`emit_log_hook`** only targets known sensitive key-management function calls, and its redaction runs after earlier hooks so masking remains the final step. It is a defense-in-depth measure, not a substitute for cautious operational handling of passphrases.
- `loaded_cipher_key_versions()` is safe to grant to runtime roles because it reveals version metadata only, not DEKs or passphrases.

Example grants:

```sql
GRANT column_encrypt_admin TO security_admin;
GRANT column_encrypt_runtime TO app_runtime;
GRANT column_encrypt_reader TO audit_reader;
```

### Key Encryption Key (KEK) vs Data Encryption Key (DEK)

| Key | Role | Storage |
|---|---|---|
| **Data Encryption Key (DEK)** | Encrypts/decrypts column data | Stored wrapped (encrypted) in `cipher_key_table`; loaded into session memory on `load_key()` |
| **Key Encryption Key (KEK) / Master Passphrase** | Wraps the DEK before storage | Never stored in the database; managed externally |

`register_cipher_key()` encrypts the DEK with the master passphrase using **AES-256 with iterated-salted S2K** (`cipher-algo=aes256, s2k-mode=3`) via `pgcrypto`'s `pgp_sym_encrypt`. `load_key()` reverses this with `pgp_sym_decrypt`.

---

## Key Rotation

To rotate the encryption key, follow these steps in a single superuser session:

```sql
-- Step 1: Disable logging and register the next key version as pending
SELECT cipher_key_disable_log();
SELECT register_cipher_key('new-data-key', 'aes', 'my-master-passphrase', 2, false);

-- Step 2: Load both versions into the session keyring
SELECT load_key_by_version('my-master-passphrase', 1);
SELECT load_key_by_version('my-master-passphrase', 2);
SET encrypt.key_version = 2;

-- Step 3: Re-encrypt all data in the encrypted column
SELECT cipher_key_reencrypt_data('public', 'secure_data', 'ssn');

-- Or rotate incrementally in batches for large tables
SELECT cipher_key_reencrypt_data_batch('public', 'secure_data', 'ssn', 5000);

-- Step 4: Activate the new version
SELECT activate_cipher_key(2);

-- Step 5: Clear the session keyring
SELECT enc_rm_key();
SELECT cipher_key_enable_log();
```

After rotation, all new sessions must call `load_key('my-master-passphrase')` to use the active key version.

## Logical Replication

`column_encrypt` replicates ciphertext, not plaintext. That means:

- subscribers must have the extension installed
- subscribers must manage and load keys independently
- wrapped keys in `cipher_key_table` are not replicated as usable session keys
- replication/apply roles should run with `encrypt.enable = off` so replication transports ciphertext rather than decrypted plaintext

Use the built-in readiness helper before publishing encrypted tables:

```sql
SELECT *
FROM cipher_key_logical_replication_check('public', 'secure_data');
```

This highlights local issues such as `wal_level`, encrypted columns, and replica identity usage.

For local end-to-end testing, the branch also includes a Docker-based logical replication harness so publisher/subscriber behavior can be exercised beyond the static readiness helper.

## Blind Indexing

For scalable equality lookups, prefer a companion blind-index column over direct comparisons on encrypted columns.
Do not rely on `<`, `<=`, `>`, or `>=` semantics for encrypted values; plaintext range ordering is intentionally unsupported.

Example:

```sql
ALTER TABLE secure_data ADD COLUMN ssn_blind_index text;

UPDATE secure_data
SET ssn_blind_index = column_encrypt_blind_index_text('888-999-2045', 'blind-index-secret');
```

The blind-index key should be managed separately from the DEK/KEK used for encryption.

---

## Logical Replication: Docker Harness

See [Logical Replication](#logical-replication) above for the conceptual model; this section documents the Docker-based integration harness that validates it end to end.

Recommended pattern:

- Use a dedicated publisher-side replication user with `ALTER ROLE ... SET encrypt.enable = off` so logical decoding emits raw ciphertext instead of decrypted plaintext.
- Use a dedicated subscriber-side subscription owner/apply-worker role with `ALTER ROLE ... SET encrypt.enable = off` so replicated ciphertext is stored directly without requiring a backend-local loaded key.
- Keep normal application sessions on the default `encrypt.enable = on` path and load keys only in roles that were explicitly granted `column_encrypt_runtime`.
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

The extension supports any symmetric cipher algorithm accepted by `pgcrypto`'s `encrypt()` and `decrypt()` functions. The algorithm name is passed as the second argument to `register_cipher_key()` and `enc_store_key()`.

Currently validated algorithm:

| Algorithm | Value |
|---|---|
| AES (Advanced Encryption Standard) | `aes` |

> **Note:** The `register_cipher_key()` function validates that the algorithm is `aes`. The DEK is always wrapped using AES-256/S2K regardless of the column encryption algorithm.

---

## License

This extension is licensed under the [PostgreSQL License](LICENSE), a permissive open-source license similar to the BSD 2-Clause license.
