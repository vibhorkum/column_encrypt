# column_encrypt

[![License: PostgreSQL](https://img.shields.io/badge/License-PostgreSQL-blue.svg)](LICENSE)
[![Language: PLpgSQL + C](https://img.shields.io/badge/Language-PLpgSQL%20%2B%20C-informational.svg)](#architecture)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Architecture](#architecture)
- [Installation](#installation)
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
- **Log masking** — an `emit_log_hook` prevents key material from appearing in PostgreSQL logs or `pg_stat_activity`
- **Row-Level Security** on `cipher_key_table` restricts direct access to the stored (wrapped) DEK
- **Key rotation** support with a built-in re-encryption helper function
- **Hash index support** on encrypted columns (`=` operator for `encrypted_text` and `encrypted_bytea`)
- **Cast support** from `bool`, `inet`, `cidr`, `xml`, and `character` to `encrypted_text`

---

## Requirements

- **PostgreSQL** (built with standard PGXS; compatible with PostgreSQL 10 and later)
- **`pgcrypto`** extension (listed as a dependency in `column_encrypt.control` and auto-installed if not already present)
- A **C compiler** and **PostgreSQL development headers** (`postgresql-devel` on RPM-based systems, `libpq-dev` / `postgresql-server-dev-*` on Debian/Ubuntu)

---

## Architecture

The extension registers two custom base types (`encrypted_text`, `encrypted_bytea`) backed by variable-length `bytea` storage.

- **On `INSERT`/`UPDATE`**: the type input function (`col_enc_text_in` / `col_enc_bytea_in`) transparently encrypts the supplied plaintext value using the session's currently loaded DEK.
- **On `SELECT`**: the type output function (`col_enc_text_out` / `col_enc_bytea_out`) transparently decrypts the stored ciphertext using the session's currently loaded DEK.
- A **2-byte key version header** is prepended to every ciphertext, enabling the extension to identify which key version was used to encrypt each value and supporting future key rotation.
- Keys are held in **`TopMemoryContext`** and securely zeroed with `secure_memset` when removed from session memory.
- An **`emit_log_hook`** masks `(...)` patterns in log messages (query text, detail, context, internal query) to prevent key material from leaking into `pg_log` or `pg_stat_activity`.

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

In each new session, load the DEK into session memory before accessing encrypted columns. Always call `cipher_key_disable_log()` first to prevent the passphrase from appearing in logs:

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
| `load_key(master_passphrase text)` | `boolean` | Decrypts the DEK from `cipher_key_table` using the master passphrase and loads it into session memory. |
| `cipher_key_disable_log()` | `boolean` | Disables `track_activities` and enables `encrypt.enable` before sensitive key operations. |
| `cipher_key_enable_log()` | `boolean` | Re-enables `track_activities` and disables `encrypt.enable` after sensitive key operations. |
| `enc_store_key(key text, algorithm text)` | `boolean` | Directly stores the current DEK in session memory (used during key rotation). |
| `enc_store_prv_key(key text, algorithm text)` | `boolean` | Stores the previous DEK in session memory (used during key rotation). |
| `enc_rm_key()` | `boolean` | Securely removes the current DEK from session memory (zeroes the key bytes). |
| `enc_rm_prv_key()` | `boolean` | Securely removes the previous DEK from session memory (zeroes the key bytes). |
| `cipher_key_reencrypt_data(schema text, table text, column text)` | `bigint` | Re-encrypts all values in the specified encrypted column using the new key (reads with previous key, writes with current key). Returns the number of rows re-encrypted. |

---

## GUC Parameters

All parameters require **superuser** (`PGC_SUSET`) to change.

| Parameter | Type | Default | Range | Description |
|---|---|---|---|---|
| `encrypt.enable` | `bool` | `on` | — | Enables or disables column encryption globally. When `off`, raw ciphertext is stored and returned without encryption/decryption. |
| `encrypt.mask_key_log` | `bool` | `on` | — | When enabled, masks `(...)` patterns in PostgreSQL log messages (query, detail, context, internal query) to prevent key material from leaking into logs. |
| `encrypt.key_version` | `int` | `1` | `1–32767` | Key version number written into the 2-byte ciphertext header. Increment this when rotating keys to track which version encrypted each value. |

---

## Security Model

- **`cipher_key_table`** has `REVOKE ALL FROM PUBLIC` and Row-Level Security (RLS) enabled. Only superusers can query it directly.
- All key operations (`register_cipher_key`, `cipher_key_reencrypt_data`, `cipher_key_disable_log`, `cipher_key_enable_log`) use **`SECURITY DEFINER`** to execute with elevated privileges.
- **`encrypt.enable`** is `PGC_SUSET` — only superusers can enable or disable encryption. This prevents unprivileged users from bypassing encryption by toggling the GUC.
- Encryption keys stored in C session memory are **zeroed with `secure_memset`** when removed, preventing key material from lingering in process memory.
- The **`emit_log_hook`** masks `(...)` patterns in all of the following log fields to prevent keys from leaking: query text, detail message, context message, and internal query message.

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
-- Step 1: Disable logging and load both old and new keys into session memory
SELECT cipher_key_disable_log();

-- Store the current (old) DEK as the previous key (used for decryption during re-encrypt)
SELECT enc_store_prv_key('old-data-key', 'aes');

-- Store the new DEK as the current key (used for encryption during re-encrypt)
SELECT enc_store_key('new-data-key', 'aes');

-- Step 2: Re-encrypt all data in the encrypted column
-- (reads each value with enc_store_prv_key, writes it back with enc_store_key)
SELECT cipher_key_reencrypt_data('public', 'secure_data', 'ssn');

-- Step 3: Replace the stored wrapped key with the new DEK wrapped by the new master passphrase
DELETE FROM cipher_key_table;
SELECT register_cipher_key('new-data-key', 'aes', 'new-master-passphrase');

-- Step 4: Clear both keys from session memory
SELECT enc_rm_prv_key();
SELECT enc_rm_key();

SELECT cipher_key_enable_log();
```

After rotation, all new sessions must call `load_key('new-master-passphrase')` to use the new key.

---

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

