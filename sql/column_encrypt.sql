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

-- Test: DEK minimum length validation (should fail with short key)
SET ROLE regress_admin;
SELECT cipher_key_disable_log();
DO $$
BEGIN
    BEGIN
        PERFORM register_cipher_key('short', 'aes', 'my-master-passphrase', 99, false);
        RAISE EXCEPTION 'register_cipher_key unexpectedly succeeded with short key';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM NOT LIKE 'EDB-ENC0049 %' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'short DEK rejected as expected';
    END;
END;
$$;
SELECT cipher_key_enable_log();
RESET ROLE;

-- Test: NULL value handling in encrypted columns
SET ROLE regress_runtime;
SELECT load_key('my-master-passphrase');
RESET ROLE;

CREATE TABLE test_null_handling (id serial, val encrypted_text);
INSERT INTO test_null_handling(val) VALUES (NULL);
INSERT INTO test_null_handling(val) VALUES ('not-null');
SELECT COUNT(*) FROM test_null_handling WHERE val IS NULL;
SELECT COUNT(*) FROM test_null_handling WHERE val IS NOT NULL;
DROP TABLE test_null_handling;

-- Test: Equality comparison across same plaintext
CREATE TABLE test_equality (id serial, val encrypted_text);
INSERT INTO test_equality(val) VALUES ('same-value');
INSERT INTO test_equality(val) VALUES ('same-value');
INSERT INTO test_equality(val) VALUES ('different-value');
SELECT COUNT(*) FROM test_equality WHERE val = 'same-value'::encrypted_text;
-- Note: COUNT(DISTINCT) not supported as encrypted types don't have ordering operators
SELECT COUNT(*) AS distinct_count FROM (
    SELECT val FROM test_equality GROUP BY val
) sub;
DROP TABLE test_equality;

-- Test: Hash consistency for encrypted values
CREATE TABLE test_hash (id serial, val encrypted_text);
INSERT INTO test_hash(val) VALUES ('hash-test');
INSERT INTO test_hash(val) VALUES ('hash-test');
-- Hash should be consistent for same plaintext value
SELECT (enc_hash_enctext(val) = enc_hash_enctext(val)) AS hash_consistent
FROM test_hash LIMIT 1;
-- Both rows with same plaintext should have same hash
SELECT COUNT(DISTINCT enc_hash_enctext(val)) AS unique_hashes FROM test_hash;
DROP TABLE test_hash;

-- Test: cipher_key_reencrypt_data with encrypt.enable=off should fail
SET encrypt.enable = off;
DO $$
BEGIN
    BEGIN
        PERFORM cipher_key_reencrypt_data('public', 'nonexistent', 'col');
        RAISE EXCEPTION 'cipher_key_reencrypt_data unexpectedly succeeded with encrypt.enable=off';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM NOT LIKE 'EDB-ENC0048 %' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'cipher_key_reencrypt_data blocked when encrypt.enable is off';
    END;
END;
$$;
SET encrypt.enable = on;

-- Test: cipher_verify_column_encryption function
CREATE TABLE test_verify_enc (id serial, secret encrypted_text);
INSERT INTO test_verify_enc(secret) VALUES ('verify-test-1'), ('verify-test-2');
SELECT check_name, status, total_rows, sampled_rows, decryptable_rows, failed_rows
  FROM cipher_verify_column_encryption('public', 'test_verify_enc', 'secret');

-- Test with invalid column
SELECT check_name, status
  FROM cipher_verify_column_encryption('public', 'test_verify_enc', 'nonexistent');

-- Test with non-encrypted column
SELECT check_name, status
  FROM cipher_verify_column_encryption('public', 'test_verify_enc', 'id');

DROP TABLE test_verify_enc;

-- Test: cipher_key_versions includes usage statistics
SELECT key_version, use_count > 0 AS has_usage FROM cipher_key_versions() WHERE key_version = 1;

-- =============================================================================
-- PRODUCTION OPERATIONS FEATURES TESTS (v3.1)
-- =============================================================================

-- Test: is_key_loaded() function
SELECT is_key_loaded() AS key_should_be_loaded;

SELECT rm_key_details();
SELECT is_key_loaded() AS key_should_not_be_loaded;

-- Reload key for remaining tests
SET ROLE regress_runtime;
SELECT load_key('my-master-passphrase');
RESET ROLE;

-- Test: cipher_encryption_stats()
CREATE TABLE test_stats_enc (id serial, ssn encrypted_text, notes encrypted_text);
INSERT INTO test_stats_enc(ssn, notes) VALUES ('111-11-1111', 'note1'), ('222-22-2222', NULL);

SELECT schema_name, table_name, column_name, row_count, null_count
  FROM cipher_encryption_stats()
 WHERE table_name = 'test_stats_enc'
 ORDER BY column_name;

-- Test: cipher_key_usage_stats()
SELECT key_version, key_state, row_count >= 0 AS has_row_count
  FROM cipher_key_usage_stats()
 WHERE key_version = 3
 LIMIT 1;

-- Test: cipher_metrics()
SELECT metric_name, metric_value >= 0 AS valid_value
  FROM cipher_metrics()
 WHERE metric_name IN ('column_encrypt_columns_total', 'column_encrypt_session_key_loaded')
 ORDER BY metric_name;

-- Test: cipher_coverage_audit() - Create tables with sensitive column names
CREATE TABLE test_audit_users (
    id serial,
    name text,
    ssn text,                -- Should be flagged as PII-HIGH
    email text,              -- Should be flagged as PII-MEDIUM
    password text,           -- Should be flagged as SECRET
    card_number text,        -- Should be flagged as PCI
    diagnosis text,          -- Should be flagged as HIPAA
    secret_data encrypted_text  -- Should be flagged as ENCRYPTED
);

SELECT schema_name, table_name, column_name, classification, is_encrypted, recommendation
  FROM cipher_coverage_audit('public')
 WHERE table_name = 'test_audit_users'
 ORDER BY column_name;

-- Test: cipher_coverage_summary()
SELECT classification, total_columns, encrypted_columns, unencrypted_columns
  FROM cipher_coverage_summary('public')
 WHERE classification IN ('PII-HIGH', 'SECRET', 'PCI', 'ENCRYPTED')
 ORDER BY classification;

DROP TABLE test_audit_users;

-- Test: Rotation job management
SET ROLE regress_admin;
SELECT cipher_key_disable_log();
SELECT register_cipher_key('rotation-test-key-v5', 'aes', 'my-master-passphrase', 5, false);
SELECT cipher_key_enable_log();
RESET ROLE;

SET ROLE regress_runtime;
SELECT load_key_by_version('my-master-passphrase', 5);
RESET ROLE;

-- Create test data with old key version
CREATE TABLE test_rotation_job (id serial PRIMARY KEY, secret encrypted_text);
INSERT INTO test_rotation_job(secret) SELECT 'secret-' || gs FROM generate_series(1, 50) gs;

-- Start rotation job
SET encrypt.key_version = 5;
SELECT cipher_start_rotation_job('public', 'test_rotation_job', 'secret', 5, 10, 0) AS job_id \gset

-- Check job was created
SELECT status, total_rows, processed_rows
  FROM cipher_rotation_progress()
 WHERE job_id = :job_id;

-- Process one batch
SELECT cipher_process_rotation_batch(:job_id) AS rows_processed;

-- Check progress
SELECT status, processed_rows > 0 AS has_progress
  FROM cipher_rotation_progress()
 WHERE job_id = :job_id;

-- Run to completion
SELECT cipher_run_rotation_job(:job_id) AS total_processed;

-- Verify completed
SELECT status, processed_rows = total_rows AS is_complete
  FROM cipher_rotation_progress()
 WHERE job_id = :job_id;

-- Test pause/resume (create new job first)
INSERT INTO test_rotation_job(secret) SELECT 'more-secret-' || gs FROM generate_series(1, 20) gs;

SET encrypt.key_version = 3;
SELECT cipher_start_rotation_job('public', 'test_rotation_job', 'secret', 3, 5, 0) AS job_id2 \gset

SELECT cipher_process_rotation_batch(:job_id2) > 0 AS batch_processed;
SELECT cipher_pause_rotation_job(:job_id2) AS paused;

SELECT status FROM cipher_rotation_progress() WHERE job_id = :job_id2;

SELECT cipher_resume_rotation_job(:job_id2) AS resumed;
SELECT status FROM cipher_rotation_progress() WHERE job_id = :job_id2;

SELECT cipher_cancel_rotation_job(:job_id2) AS cancelled;
SELECT status FROM cipher_rotation_progress() WHERE job_id = :job_id2;

-- Cleanup
DROP TABLE test_rotation_job;
DROP TABLE test_stats_enc;

SELECT rm_key_details();
