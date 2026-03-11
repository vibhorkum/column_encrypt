-- column_encryption regression tests
-- These tests require the column_encryption extension and pgcrypto.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION column_encryption VERSION '2.0';

-- -----------------------------------------------------------------------
-- Setup: enable encryption and register a key with a master passphrase
-- -----------------------------------------------------------------------

SELECT cipher_key_disable_log();

SELECT register_cipher_key('my-secret-data-key-32bytes-longg', 'aes', 'my-master-passphrase');

SELECT load_key('my-master-passphrase');

-- -----------------------------------------------------------------------
-- Test 1: Basic encrypted_text roundtrip
-- -----------------------------------------------------------------------

CREATE TABLE enc_text_test (
    id   serial PRIMARY KEY,
    val  encrypted_text
);

INSERT INTO enc_text_test(val) VALUES ('hello world');
INSERT INTO enc_text_test(val) VALUES ('sensitive data 123');

SELECT val FROM enc_text_test ORDER BY id;

-- -----------------------------------------------------------------------
-- Test 2: Basic encrypted_bytea roundtrip
-- -----------------------------------------------------------------------

CREATE TABLE enc_bytea_test (
    id   serial PRIMARY KEY,
    val  encrypted_bytea
);

INSERT INTO enc_bytea_test(val) VALUES ('\xdeadbeef');
INSERT INTO enc_bytea_test(val) VALUES ('\xcafebabe');

SELECT val FROM enc_bytea_test ORDER BY id;

-- -----------------------------------------------------------------------
-- Test 3: Equality operator on encrypted_text (ciphertext-level comparison)
-- -----------------------------------------------------------------------

SELECT val = val AS self_equal FROM enc_text_test WHERE id = 1;

-- -----------------------------------------------------------------------
-- Test 4: encrypt.enable is superuser-only (PGC_SUSET)
-- This should raise an error for a normal user.
-- -----------------------------------------------------------------------

CREATE ROLE enc_test_user LOGIN PASSWORD 'testpass';

\connect - enc_test_user
SET encrypt.enable = off;

\connect - postgres

DROP ROLE enc_test_user;

-- -----------------------------------------------------------------------
-- Test 5: Wrong algorithm rejected
-- -----------------------------------------------------------------------

SELECT cipher_key_disable_log();

SELECT register_cipher_key('somekey', 'bf', 'master');

-- -----------------------------------------------------------------------
-- Test 6: Key rotation via cipher_key_reencrypt_data
-- Store old key as previous, set new key, then re-encrypt
-- -----------------------------------------------------------------------

SELECT enc_rm_prv_key();
SELECT enc_store_prv_key('my-secret-data-key-32bytes-longg', 'aes');
SELECT enc_store_key('new-secret-data-key-32bytes-long', 'aes');

SELECT cipher_key_disable_log();
SELECT cipher_key_reencrypt_data('public', 'enc_text_test', 'val');

-- Switch to new key for reads
SELECT enc_rm_prv_key();
SELECT val FROM enc_text_test ORDER BY id;

-- -----------------------------------------------------------------------
-- Cleanup
-- -----------------------------------------------------------------------

SELECT enc_rm_key();
SELECT enc_rm_prv_key();
SELECT cipher_key_enable_log();

DROP TABLE enc_text_test;
DROP TABLE enc_bytea_test;
