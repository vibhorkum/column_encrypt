-- column_encrypt regression tests

-- Install pgcrypto (required dependency) and then load the extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS column_encrypt;

-- Disable logging before key operations
SELECT cipher_key_disable_log();

-- Register a key with a separate master passphrase (KEK)
SELECT register_cipher_key('my-data-encryption-key', 'aes', 'my-master-passphrase');

-- Load the key using the master passphrase
SELECT load_key('my-master-passphrase');

-- Re-enable logging
SELECT cipher_key_enable_log();

--
-- Basic encrypted_text roundtrip
--
SELECT cipher_key_disable_log();
SELECT load_key('my-master-passphrase');

CREATE TABLE test_enc_text (id serial, ssn encrypted_text);
INSERT INTO test_enc_text(ssn) VALUES ('123-45-6789');
INSERT INTO test_enc_text(ssn) VALUES ('987-65-4321');

-- Should return decrypted values
SELECT ssn FROM test_enc_text ORDER BY id;

-- Cleanup
DROP TABLE test_enc_text;

--
-- Basic encrypted_bytea roundtrip
--
CREATE TABLE test_enc_bytea (id serial, data encrypted_bytea);
INSERT INTO test_enc_bytea(data) VALUES ('hello'::bytea);
INSERT INTO test_enc_bytea(data) VALUES ('world'::bytea);

-- Should return decrypted values
SELECT data FROM test_enc_bytea ORDER BY id;

-- Cleanup
DROP TABLE test_enc_bytea;

--
-- Equality operator on encrypted_text
--
CREATE TABLE test_eq (id serial, val encrypted_text);
INSERT INTO test_eq(val) VALUES ('secret');
INSERT INTO test_eq(val) VALUES ('other');

SELECT COUNT(*) FROM test_eq WHERE val = 'secret'::encrypted_text;

DROP TABLE test_eq;

--
-- UNIQUE constraint on encrypted_text (btree operator class)
--
CREATE TABLE test_unique_enc (id serial, val encrypted_text UNIQUE);
INSERT INTO test_unique_enc(val) VALUES ('alpha');
INSERT INTO test_unique_enc(val) VALUES ('beta');

-- Should fail: duplicate value
INSERT INTO test_unique_enc(val) VALUES ('alpha');

-- Should have exactly 2 rows
SELECT COUNT(*) FROM test_unique_enc;

DROP TABLE test_unique_enc;

-- Clear the key from memory
SELECT rm_key_details();
