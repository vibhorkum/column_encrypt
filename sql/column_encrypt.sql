-- column_encrypt regression tests

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS column_encrypt;

SELECT cipher_key_disable_log();
SELECT register_cipher_key('my-data-encryption-key-v1', 'aes', 'my-master-passphrase');
SELECT load_key('my-master-passphrase');
SELECT cipher_key_enable_log();

CREATE TABLE test_enc_text (id serial, ssn encrypted_text);
INSERT INTO test_enc_text(ssn) VALUES ('123-45-6789');
INSERT INTO test_enc_text(ssn) VALUES ('987-65-4321');
SELECT ssn FROM test_enc_text ORDER BY id;
SELECT COUNT(*) FROM test_enc_text WHERE ssn = '123-45-6789'::encrypted_text;

CREATE TABLE test_enc_bytea (id serial, data encrypted_bytea);
INSERT INTO test_enc_bytea(data) VALUES ('hello'::bytea);
INSERT INTO test_enc_bytea(data) VALUES ('world'::bytea);
SELECT data FROM test_enc_bytea ORDER BY id;

SELECT cipher_key_disable_log();
SELECT register_cipher_key('my-data-encryption-key-v2', 'aes', 'my-master-passphrase', 2, false);
SELECT load_key_by_version('my-master-passphrase', 1);
SELECT load_key_by_version('my-master-passphrase', 2);
SET encrypt.key_version = 2;
SELECT cipher_key_reencrypt_data('public', 'test_enc_text', 'ssn');
SELECT cipher_key_reencrypt_data('public', 'test_enc_bytea', 'data');
SELECT activate_cipher_key(2);
SELECT cipher_key_enable_log();

SELECT ssn FROM test_enc_text ORDER BY id;
SELECT data FROM test_enc_bytea ORDER BY id;
SELECT key_version, algorithm, is_active FROM cipher_key_versions() ORDER BY key_version;
SELECT COUNT(*) FROM cipher_key_logical_replication_check('public', 'test_enc_text');

DROP TABLE test_enc_text;
DROP TABLE test_enc_bytea;

SELECT rm_key_details();
