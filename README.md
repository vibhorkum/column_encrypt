# column_encrypt

## Motivation
The main motivation behind this module is that PostgreSQL should be able to provide data types which can work as Transparent Column Level encryption i.e Database users should be able to use their keys when they are inserting data in a table and data should be encrypted in a specific column. Database users who has right key should be able to access the data transparently without any modification in their SQLs.

Column encryption module comes with following two data types:
1. encrypted_text (data type for encrypted Text)
2. encrypted_bytea (data type for encrypted bytea)

## Installation steps

To install this module please use following steps:
1. Copy the source code from repository.
2. set pg_config binary location in PATH environment variable
3. Execute following command to install this module
```sql
make
make install
```

After compiling the module, follow the steps given below:
1. update shared_preload_libraries parameter of postgresql.conf of PostgreSQL
     shared_preload_libraries = '$libdir/column_encrypt'
2. Restart the PostgreSQL using pg_ctl or systemctl command.
3. Use following command to install this extension in target database as given below:
```sql
psql -h server.hostname.org -p 5444 -c "CREATE EXTENSION column_encrypt;" dbname
```

## How to use

1. Connect to database as a superuser and register your key using a separate master passphrase (Key Encryption Key):
```sql
SELECT cipher_key_disable_log();
SELECT register_cipher_key('AES-DBC-AEF-GHI-JKL', 'aes', 'my-master-passphrase');
SELECT cipher_key_enable_log();
```
2. After registering the key, reconnect to a session and load your key using the master passphrase:
```sql
SELECT cipher_key_disable_log();
SELECT load_key('my-master-passphrase');
```
3.  Create a table using data encrypt_bytea/encrypt_text data-types and insert some records
```sql
CREATE TABLE secure_data(id SERIAL, ssn ENCRYPTED_TEXT);
INSERT INTO secure_data(ssn) VALUES('888-999-2045');
INSERT INTO secure_data(ssn) VALUES('888-999-2046');
INSERT INTO secure_data(ssn) VALUES('888-999-2047');
```
4. Verify within the session you can access the rows:
```sql
test=# SELECT * FROM secure_data;
 id |     ssn      
----+--------------
  1 | 888-999-2045
  2 | 888-999-2046
  3 | 888-999-2047
(3 rows)
```
5. Exit from the session and connect with different session and try to Read the data:
```sql
test=# SELECT * FROM secure_data;
ERROR:  cannot decrypt data, because key was not set
```
Above result was expected since key was not set.
6. Now try to set a wrong key:
```sql
test=# SELECT cipher_key_disable_log();
 cipher_key_disable_log 
------------------------
 t
(1 row)

test=# SELECT load_key('wrong-passphrase');
ERROR:  EDB-ENC0012 cipher key is not correct
```
Above was also expected because user tried to pass the wrong key.

## Security

### Key Encryption Key (KEK) vs Data Encryption Key (DEK)

The extension uses a two-tier key model:
- **Data Encryption Key (DEK)**: The key used to actually encrypt/decrypt column data. Stored in `cipher_key_table` in encrypted form.
- **Key Encryption Key (KEK) / Master Passphrase**: Used to wrap (encrypt) the DEK before storing it in `cipher_key_table`. The KEK should be managed externally and never stored in the database.

The `register_cipher_key(data_key, algorithm, master_passphrase)` function encrypts the DEK with the master passphrase using AES-256 with iterated-salted S2K (s2k-mode=3) before storing it. The `load_key(master_passphrase)` function decrypts the DEK into session memory using the master passphrase.

### GUC Parameters

- **`encrypt.enable`** (superuser only): Enables/disables column encryption. Requires superuser privileges to change. When off, raw ciphertext is stored/returned.
- **`encrypt.mask_key_log`** (superuser only): When enabled (default: on), masks query log messages matching `(...)` patterns to prevent key material from appearing in logs.
- **`encrypt.key_version`** (superuser only): The key version number written into the ciphertext header. Default: 1. Range: 1–32767.

### `cipher_key_table` Access Control

The `cipher_key_table` has restricted access:
- `REVOKE ALL` from `PUBLIC`
- Row-Level Security enabled with a policy allowing only superusers to query it directly
- All key operations go through `SECURITY DEFINER` functions

### `encrypt.enable` requires superuser

The `encrypt.enable` GUC is `PGC_SUSET` — only superusers can change it. This prevents non-privileged users from bypassing encryption.

## Key Rotation

To rotate the encryption key:

```sql
-- Step 1: Load old and new keys
SELECT cipher_key_disable_log();

-- Store the current (old) key as the previous key
SELECT enc_store_prv_key('old-data-key', 'aes');

-- Store the new data key as the current key
SELECT enc_store_key('new-data-key', 'aes');

-- Step 2: Re-encrypt all data in the encrypted column
SELECT cipher_key_reencrypt_data('public', 'secure_data', 'ssn');

-- Step 3: Update cipher_key_table with the new key wrapped by the new master passphrase
DELETE FROM cipher_key_table;
SELECT register_cipher_key('new-data-key', 'aes', 'new-master-passphrase');

-- Step 4: Clear keys from memory
SELECT enc_rm_prv_key();
SELECT enc_rm_key();

SELECT cipher_key_enable_log();
```

After rotation, users must call `load_key('new-master-passphrase')` in new sessions.

