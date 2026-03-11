# column_encryption

## Motivation
The main motivation behind this module is that EDB Postgres should be able to provide data types which can work as Transparent Column Level encryption i.e Database users should be able to use their keys when they are inserting data in a table and data should be encrypted in a specific column. Database users who has right key should be able to access the data transparently without any modification in their SQLs.

Column encryption module comes with following two data types:
1. encrypted_text (data type for encrypted Text)
2. encrypted_bytea (data type for encrypted bytea)

## Installation steps

To install this module please use following steps:
1. Copy the source code from repository.
2. Set `pg_config` binary location in PATH environment variable.
3. Execute the following commands to build and install:
```bash
make
make install
```

After compiling the module, follow the steps given below:
1. Update `shared_preload_libraries` in `postgresql.conf`:
   ```
   shared_preload_libraries = '$libdir/column_encryption'
   ```
2. Restart PostgreSQL using `pg_ctl` or `systemctl`.
3. Install the extension in the target database (version 2.0 is the default):
```sql
psql -h server.hostname.org -p 5432 -c "CREATE EXTENSION column_encryption;" dbname
```

## How to use

### Key Concepts: DEK and KEK
This extension uses a two-key hierarchy:
- **Data Encryption Key (DEK)**: The key that actually encrypts your column data. Stored
  wrapped inside `cipher_key_table`.
- **Key Encryption Key / Master Passphrase (KEK)**: A separate passphrase used to wrap (protect)
  the DEK at rest. The KEK is **never stored in the database** — you must supply it each session.

### Registering a key (superuser only)
```sql
-- First suppress logging so the key does not appear in pg_stat_activity
SELECT cipher_key_disable_log();

-- register_cipher_key(data_key, algorithm, master_passphrase)
-- Only 'aes' algorithm is supported. Blowfish ('bf') has been removed.
SELECT register_cipher_key('my-secret-data-key-32bytes-longg', 'aes', 'my-master-passphrase');

SELECT cipher_key_enable_log();
```

### Loading the key each session
```sql
SELECT cipher_key_disable_log();
-- load_key(master_passphrase) — decrypts the stored DEK using the KEK
SELECT load_key('my-master-passphrase');
```

### Creating encrypted tables and inserting data
```sql
CREATE TABLE secure_data(id SERIAL, ssn ENCRYPTED_TEXT);
INSERT INTO secure_data(ssn) VALUES('888-999-2045');
INSERT INTO secure_data(ssn) VALUES('888-999-2046');
INSERT INTO secure_data(ssn) VALUES('888-999-2047');
```

### Reading data
```sql
test=# SELECT * FROM secure_data;
 id |     ssn      
----+--------------
  1 | 888-999-2045
  2 | 888-999-2046
  3 | 888-999-2047
(3 rows)
```

If the key is not loaded (e.g., new session):
```sql
test=# SELECT * FROM secure_data;
ERROR:  cannot decrypt data, because key was not set
```

## GUC Parameters

| Parameter | Type | Context | Default | Description |
|-----------|------|---------|---------|-------------|
| `encrypt.enable` | bool | `PGC_SUSET` | `on` | Enable/disable column encryption. **Superuser only.** |
| `encrypt.mask_key_log` | bool | `PGC_SUSET` | `on` | Mask key material in error logs and context messages. **Superuser only.** |
| `encrypt.key_version` | int | `PGC_SUSET` | `1` | Key version written into each ciphertext header (1–32767). **Superuser only.** |

> **Note**: `encrypt.enable` requires superuser privilege to change (`PGC_SUSET`). A non-superuser cannot set it to `off` to bypass encryption.

## Security

### KEK vs DEK separation
- The **DEK** (Data Encryption Key) is the AES key that encrypts column values. It is stored encrypted inside `cipher_key_table`, wrapped by the KEK using PGP symmetric encryption (`aes256`, iterated+salted KDF / `s2k-mode=3`).
- The **KEK** (Master Passphrase) never touches the database at rest. It is passed as an argument to `load_key()` and `register_cipher_key()` only within a session where `cipher_key_disable_log()` has been called first.

### `cipher_key_table` access control
The key table has Row-Level Security enabled and `PUBLIC` access revoked. Only superusers (who bypass RLS) can query it directly. Regular users access encrypted columns transparently via the `SECURITY DEFINER` extension functions.

### Log masking
`encrypt.mask_key_log = on` (the default) hooks into PostgreSQL's error reporting and replaces any `(...)` sections in log messages with `(*****)`, preventing key material from leaking into server logs, `pg_stat_activity`, or error detail messages.

## Key Rotation

Key rotation requires the old DEK to be loaded as the "previous key" while the new DEK is set as the current key. The `cipher_key_reencrypt_data()` function then re-encrypts every value in the column transparently.

### Step-by-step key rotation procedure
```sql
-- Step 1: Suppress logging
SELECT cipher_key_disable_log();

-- Step 2: Load old key as previous key
SELECT enc_store_prv_key('old-secret-data-key-32bytes-long', 'aes');

-- Step 3: Load new key as current key
SELECT enc_store_key('new-secret-data-key-32bytes-long', 'aes');

-- Step 4: Re-encrypt each column that uses encryption
-- cipher_key_reencrypt_data(schema, table, column)
SELECT cipher_key_reencrypt_data('public', 'secure_data', 'ssn');

-- Step 5: Clear old key from memory
SELECT enc_rm_prv_key();

-- Step 6: Update cipher_key_table with new DEK wrapped under new (or same) master passphrase
TRUNCATE cipher_key_table;
SELECT register_cipher_key('new-secret-data-key-32bytes-long', 'aes', 'new-master-passphrase');

-- Step 7: Re-enable logging
SELECT cipher_key_enable_log();
```

> The `cipher_key_reencrypt_data()` function validates the schema/table/column name against a strict regex to prevent SQL injection.

## Running regression tests

```bash
make installcheck
```
