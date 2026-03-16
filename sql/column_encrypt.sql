-- column_encrypt regression tests

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS column_encrypt;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'regress_admin') THEN
        EXECUTE 'DROP ROLE regress_admin';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'regress_runtime') THEN
        EXECUTE 'DROP ROLE regress_runtime';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'regress_reader') THEN
        EXECUTE 'DROP ROLE regress_reader';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'regress_app') THEN
        EXECUTE 'DROP ROLE regress_app';
    END IF;
END;
$$;

CREATE ROLE regress_admin LOGIN;
CREATE ROLE regress_runtime LOGIN;
CREATE ROLE regress_reader LOGIN;
CREATE ROLE regress_app LOGIN;

GRANT column_encrypt_admin TO regress_admin;
GRANT column_encrypt_runtime TO regress_runtime;
GRANT column_encrypt_reader TO regress_reader;

SELECT has_function_privilege('regress_admin', 'register_cipher_key(text,text,text)', 'EXECUTE');
SELECT has_function_privilege('regress_runtime', 'load_key(text)', 'EXECUTE');
SELECT has_function_privilege('regress_runtime', 'register_cipher_key(text,text,text)', 'EXECUTE');
SELECT has_function_privilege('regress_reader', 'cipher_key_versions()', 'EXECUTE');
SELECT has_function_privilege('regress_app', 'load_key(text)', 'EXECUTE');
SELECT has_function_privilege('regress_runtime', 'loaded_cipher_key_versions()', 'EXECUTE');
SELECT has_function_privilege('regress_app', 'rm_key_details()', 'EXECUTE');

SET ROLE regress_admin;
SELECT cipher_key_disable_log();
SELECT register_cipher_key('my-data-encryption-key-v1', 'aes', 'my-master-passphrase');
SELECT cipher_key_enable_log();
RESET ROLE;

SET ROLE regress_runtime;
SELECT load_key('my-master-passphrase');
SELECT loaded_cipher_key_versions();
RESET ROLE;

SET ROLE regress_runtime;
DO $$
BEGIN
    BEGIN
        PERFORM register_cipher_key('unexpected', 'aes', 'unexpected');
        RAISE EXCEPTION 'register_cipher_key unexpectedly succeeded';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'register_cipher_key denied for regress_runtime';
    END;
END;
$$;
RESET ROLE;

SET ROLE regress_app;
DO $$
BEGIN
    BEGIN
        PERFORM load_key('my-master-passphrase');
        RAISE EXCEPTION 'load_key unexpectedly succeeded';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'load_key denied for regress_app';
    END;
END;
$$;
RESET ROLE;

SET ROLE regress_runtime;
DO $$
BEGIN
    BEGIN
        PERFORM revoke_cipher_key(1);
        RAISE EXCEPTION 'revoke_cipher_key unexpectedly succeeded';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'revoke_cipher_key denied for regress_runtime';
    END;
END;
$$;
RESET ROLE;

SET ROLE regress_app;
DO $$
BEGIN
    BEGIN
        PERFORM rm_key_details();
        RAISE EXCEPTION 'rm_key_details unexpectedly succeeded';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'rm_key_details denied for regress_app';
    END;
END;
$$;
RESET ROLE;

CREATE TABLE test_enc_text (id serial, ssn encrypted_text);
INSERT INTO test_enc_text(ssn) VALUES ('123-45-6789');
INSERT INTO test_enc_text(ssn) VALUES ('987-65-4321');
SELECT ssn FROM test_enc_text ORDER BY id;
SELECT COUNT(*) FROM test_enc_text WHERE ssn = '123-45-6789'::encrypted_text;
SELECT column_encrypt_blind_index_text('123-45-6789', 'blind-index-secret');

CREATE TABLE test_enc_bytea (id serial, data encrypted_bytea);
INSERT INTO test_enc_bytea(data) VALUES ('hello'::bytea);
INSERT INTO test_enc_bytea(data) VALUES ('world'::bytea);
SELECT data FROM test_enc_bytea ORDER BY id;
SELECT column_encrypt_blind_index_bytea('hello'::bytea, 'blind-index-secret');
SELECT loaded_cipher_key_versions();
SELECT col_enc_send_text('123-45-6789'::encrypted_text);
SELECT col_enc_send_bytea('hello'::encrypted_bytea);

SET encrypt.enable = off;
CREATE TABLE test_off_mode_text (id serial, val encrypted_text);
INSERT INTO test_off_mode_text(val) VALUES ('alpha'), ('beta');
SELECT COUNT(*) FROM test_off_mode_text WHERE val = 'alpha'::encrypted_text;
SELECT enc_hash_enctext('alpha'::encrypted_text) = enc_hash_enctext('alpha'::encrypted_text);

CREATE TABLE test_off_mode_bytea (id serial, val encrypted_bytea);
INSERT INTO test_off_mode_bytea(val) VALUES ('abc'::bytea), ('xyz'::bytea);
SELECT COUNT(*) FROM test_off_mode_bytea WHERE val = 'abc'::encrypted_bytea;
SELECT enc_hash_encbytea('abc'::encrypted_bytea) = enc_hash_encbytea('abc'::encrypted_bytea);
SET encrypt.enable = on;

SET ROLE regress_admin;
SELECT cipher_key_disable_log();
SELECT register_cipher_key('my-data-encryption-key-v2', 'aes', 'my-master-passphrase', 2, false);
SELECT cipher_key_enable_log();
RESET ROLE;

SET encrypt.key_version = 1;
SET ROLE regress_runtime;
SELECT load_key_by_version('my-master-passphrase', 1);
SELECT load_key_by_version('my-master-passphrase', 2);
SHOW encrypt.key_version;
RESET ROLE;

SET encrypt.key_version = 1;
DO $$
BEGIN
    BEGIN
        PERFORM load_key_by_version('wrong-passphrase', 2);
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM NOT LIKE 'EDB-ENC0012 %' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'load_key_by_version failed as expected';
    END;
END;
$$;
SHOW encrypt.key_version;
SELECT loaded_cipher_key_versions();

SET encrypt.key_version = 2;
SET ROLE regress_admin;
SELECT cipher_key_reencrypt_data('public', 'test_enc_text', 'ssn');
SELECT cipher_key_reencrypt_data('public', 'test_enc_bytea', 'data');
SELECT activate_cipher_key(2);
RESET ROLE;

SELECT ssn FROM test_enc_text ORDER BY id;
SELECT data FROM test_enc_bytea ORDER BY id;

CREATE TABLE test_batch_rotate (id integer PRIMARY KEY, val encrypted_text);
INSERT INTO test_batch_rotate(id, val)
SELECT gs, format('secret-%s', gs)
FROM generate_series(1, 100) AS gs;

SET ROLE regress_admin;
SELECT cipher_key_disable_log();
SELECT register_cipher_key('my-data-encryption-key-v3', 'aes', 'my-master-passphrase', 3, false);
SELECT cipher_key_enable_log();
RESET ROLE;

SET ROLE regress_runtime;
SELECT load_key_by_version('my-master-passphrase', 3);
RESET ROLE;

SET encrypt.enable = off;
DO $$
BEGIN
    BEGIN
        PERFORM cipher_key_reencrypt_data_batch('public', 'test_batch_rotate', 'val', 15);
        RAISE EXCEPTION 'cipher_key_reencrypt_data_batch unexpectedly succeeded with encrypt.enable=off';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM NOT LIKE 'EDB-ENC0048 %' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'cipher_key_reencrypt_data_batch blocked when encrypt.enable is off';
    END;
END;
$$;
SET encrypt.enable = on;

SET encrypt.key_version = 3;
DO $$
DECLARE
    moved bigint;
    total bigint := 0;
BEGIN
    LOOP
        moved := cipher_key_reencrypt_data_batch('public', 'test_batch_rotate', 'val', 15);
        EXIT WHEN moved = 0;
        total := total + moved;
    END LOOP;
    RAISE NOTICE 'batch rotated % rows', total;
END;
$$;

SET ROLE regress_admin;
SELECT activate_cipher_key(3);
RESET ROLE;

SELECT COUNT(*) FROM test_batch_rotate WHERE val::text LIKE 'secret-%';
SELECT key_version, algorithm, key_state FROM cipher_key_versions() ORDER BY key_version;

SET ROLE regress_admin;
SELECT cipher_key_disable_log();
SELECT register_cipher_key('my-data-encryption-key-v4', 'aes', 'my-master-passphrase', 4, false);
SELECT revoke_cipher_key(4);
SELECT cipher_key_enable_log();
RESET ROLE;

SET ROLE regress_runtime;
SELECT load_key_by_version('my-master-passphrase', 4);
RESET ROLE;

SET ROLE regress_admin;
SELECT activate_cipher_key(4);
RESET ROLE;

SELECT COUNT(*) FROM cipher_key_logical_replication_check('public', 'test_enc_text');

ALTER TABLE test_batch_rotate REPLICA IDENTITY FULL;
SELECT COUNT(*) FROM cipher_key_logical_replication_check('public', 'test_batch_rotate');

DROP TABLE test_enc_text;
DROP TABLE test_enc_bytea;
DROP TABLE test_batch_rotate;
DROP TABLE test_off_mode_text;
DROP TABLE test_off_mode_bytea;

SELECT rm_key_details();
