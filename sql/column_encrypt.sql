-- column_encrypt regression tests (v4.0 API)
--
-- Tests the simplified encrypt.* schema API introduced in v4.0.
-- Uses single column_encrypt_user role instead of 3-role system.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS column_encrypt;

-- =============================================================================
-- ROLE SETUP
-- =============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'regress_user') THEN
        EXECUTE 'DROP ROLE regress_user';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'regress_unprivileged') THEN
        EXECUTE 'DROP ROLE regress_unprivileged';
    END IF;
END;
$$;

CREATE ROLE regress_user LOGIN;
CREATE ROLE regress_unprivileged LOGIN;

-- Grant the unified role
GRANT column_encrypt_user TO regress_user;

-- Grant CREATE on public schema (required for PG15+ where public has no default CREATE)
GRANT CREATE ON SCHEMA public TO regress_user;

-- Verify privilege grants
SELECT has_function_privilege('regress_user', 'encrypt.register_key(text,text,boolean)', 'EXECUTE');
SELECT has_function_privilege('regress_user', 'encrypt.load_key(text,boolean)', 'EXECUTE');
SELECT has_function_privilege('regress_user', 'encrypt.unload_key()', 'EXECUTE');
SELECT has_function_privilege('regress_user', 'encrypt.keys()', 'EXECUTE');
SELECT has_function_privilege('regress_user', 'encrypt.rotate(text,text,text,integer)', 'EXECUTE');

-- Unprivileged user should not have access
SELECT has_function_privilege('regress_unprivileged', 'encrypt.register_key(text,text,boolean)', 'EXECUTE');
SELECT has_function_privilege('regress_unprivileged', 'encrypt.load_key(text,boolean)', 'EXECUTE');

-- =============================================================================
-- KEY REGISTRATION (no disable_log ceremony needed - automatic log masking)
-- =============================================================================

SET ROLE regress_user;

-- Register first key (auto-assigned version 1, active by default)
SELECT encrypt.register_key('my-data-encryption-key-v1', 'my-master-passphrase');

-- Check key was registered
SELECT key_id, key_state, algorithm FROM encrypt.keys() WHERE key_id = 1;

RESET ROLE;

-- =============================================================================
-- KEY LOADING
-- =============================================================================

SET ROLE regress_user;

-- Load key into session
SELECT encrypt.load_key('my-master-passphrase');

-- Verify key is loaded
SELECT loaded_cipher_key_versions();

-- Check status
SELECT key_loaded, active_key_version FROM encrypt.status();

RESET ROLE;

-- =============================================================================
-- ENCRYPTED COLUMN USAGE
-- =============================================================================

-- Test encrypted_text type
CREATE TABLE test_enc_text (id serial, ssn encrypted_text);
INSERT INTO test_enc_text(ssn) VALUES ('123-45-6789');
INSERT INTO test_enc_text(ssn) VALUES ('987-65-4321');
SELECT ssn FROM test_enc_text ORDER BY id;

-- Equality comparison
SELECT COUNT(*) FROM test_enc_text WHERE ssn = '123-45-6789'::encrypted_text;

-- Test encrypted_bytea type
CREATE TABLE test_enc_bytea (id serial, data encrypted_bytea);
INSERT INTO test_enc_bytea(data) VALUES ('hello'::bytea);
INSERT INTO test_enc_bytea(data) VALUES ('world'::bytea);
SELECT data FROM test_enc_bytea ORDER BY id;

-- =============================================================================
-- BLIND INDEX
-- =============================================================================

-- Basic blind index generation
SELECT encrypt.blind_index('123-45-6789', 'blind-index-secret');

-- Consistency test: same input should produce same output
SELECT encrypt.blind_index('test-value', 'secret-key') = encrypt.blind_index('test-value', 'secret-key') AS consistent;

-- Different inputs produce different outputs
SELECT encrypt.blind_index('value-a', 'key') <> encrypt.blind_index('value-b', 'key') AS different_values;

-- Different keys produce different outputs
SELECT encrypt.blind_index('same-value', 'key-1') <> encrypt.blind_index('same-value', 'key-2') AS different_keys;

-- Output format: should be 64 hex characters (SHA-256 = 256 bits = 64 hex chars)
SELECT length(encrypt.blind_index('test', 'key')) AS hex_length;

-- STRICT function returns NULL for NULL inputs
SELECT encrypt.blind_index(NULL, 'key') IS NULL AS null_value_returns_null;
SELECT encrypt.blind_index('value', NULL) IS NULL AS null_key_returns_null;

-- Practical use case: searchable blind index column
CREATE TABLE test_blind_index (
    id serial PRIMARY KEY,
    ssn_encrypted encrypted_text,
    ssn_blind_index text
);

-- Insert data with both encrypted value and blind index
INSERT INTO test_blind_index (ssn_encrypted, ssn_blind_index)
VALUES ('123-45-6789', encrypt.blind_index('123-45-6789', 'blind-secret'));
INSERT INTO test_blind_index (ssn_encrypted, ssn_blind_index)
VALUES ('987-65-4321', encrypt.blind_index('987-65-4321', 'blind-secret'));
INSERT INTO test_blind_index (ssn_encrypted, ssn_blind_index)
VALUES ('555-55-5555', encrypt.blind_index('555-55-5555', 'blind-secret'));

-- Search using blind index (efficient lookup without decrypting all rows)
SELECT id, ssn_encrypted
FROM test_blind_index
WHERE ssn_blind_index = encrypt.blind_index('123-45-6789', 'blind-secret');

-- Verify we can find the correct record
SELECT COUNT(*) AS found_count
FROM test_blind_index
WHERE ssn_blind_index = encrypt.blind_index('987-65-4321', 'blind-secret');

-- Non-matching search returns no rows
SELECT COUNT(*) AS not_found_count
FROM test_blind_index
WHERE ssn_blind_index = encrypt.blind_index('000-00-0000', 'blind-secret');

DROP TABLE test_blind_index;

-- =============================================================================
-- ENCRYPT.ENABLE = OFF MODE
-- =============================================================================

SET encrypt.enable = off;

CREATE TABLE test_off_mode_text (id serial, val encrypted_text);
INSERT INTO test_off_mode_text(val) VALUES ('alpha'), ('beta');
SELECT COUNT(*) FROM test_off_mode_text WHERE val = 'alpha'::encrypted_text;

-- Hash consistency in off mode
SELECT enc_hash_enctext('alpha'::encrypted_text) = enc_hash_enctext('alpha'::encrypted_text);

CREATE TABLE test_off_mode_bytea (id serial, val encrypted_bytea);
INSERT INTO test_off_mode_bytea(val) VALUES ('abc'::bytea), ('xyz'::bytea);
SELECT COUNT(*) FROM test_off_mode_bytea WHERE val = 'abc'::encrypted_bytea;

SET encrypt.enable = on;

-- =============================================================================
-- KEY VERSIONING AND ROTATION
-- =============================================================================

SET ROLE regress_user;

-- Register second key version (inactive by default)
SELECT encrypt.register_key('my-data-encryption-key-v2', 'my-master-passphrase', false);

-- Load all key versions for rotation
SELECT encrypt.load_key('my-master-passphrase', true);

-- Verify both keys loaded
SELECT loaded_cipher_key_versions();

-- Activate v2 for new encryptions
SELECT encrypt.activate_key(2);

-- Check key states
SELECT key_id, key_state FROM encrypt.keys() ORDER BY key_id;

RESET ROLE;

-- Rotate data to new key version
SET encrypt.key_version = 2;

SET ROLE regress_user;
SELECT encrypt.rotate('public', 'test_enc_text', 'ssn');
SELECT encrypt.rotate('public', 'test_enc_bytea', 'data');
RESET ROLE;

-- Verify data still readable after rotation
SELECT ssn FROM test_enc_text ORDER BY id;
SELECT data FROM test_enc_bytea ORDER BY id;

-- =============================================================================
-- BATCH ROTATION
-- =============================================================================

CREATE TABLE test_batch_rotate (id integer PRIMARY KEY, val encrypted_text);
INSERT INTO test_batch_rotate(id, val)
SELECT gs, format('secret-%s', gs)
FROM generate_series(1, 100) AS gs;

SET ROLE regress_user;

-- Register third key
SELECT encrypt.register_key('my-data-encryption-key-v3', 'my-master-passphrase', false);

-- Load v3
SELECT encrypt.load_key('my-master-passphrase', true);

-- Activate v3
SELECT encrypt.activate_key(3);

RESET ROLE;

-- Batch rotation with limit
SET encrypt.key_version = 3;

SET ROLE regress_user;
DO $$
DECLARE
    moved bigint;
    total bigint := 0;
BEGIN
    LOOP
        moved := encrypt.rotate('public', 'test_batch_rotate', 'val', 15);
        EXIT WHEN moved = 0;
        total := total + moved;
    END LOOP;
    RAISE NOTICE 'batch rotated % rows', total;
END;
$$;
RESET ROLE;

-- Verify all data intact
SELECT COUNT(*) FROM test_batch_rotate WHERE val::text LIKE 'secret-%';

-- Check final key states
SELECT key_id, key_state FROM encrypt.keys() ORDER BY key_id;

-- =============================================================================
-- KEY REVOCATION
-- =============================================================================

SET ROLE regress_user;

-- Register and immediately revoke a key (DEK must be at least 16 bytes)
SELECT encrypt.register_key('revoked-key-data-v4', 'my-master-passphrase', false);
SELECT encrypt.revoke_key(4);

-- Verify revoked key state
SELECT key_id, key_state FROM encrypt.keys() WHERE key_id = 4;

-- Cannot activate revoked key
SELECT encrypt.activate_key(4);

RESET ROLE;

-- =============================================================================
-- VERIFICATION
-- =============================================================================

SET ROLE regress_user;

-- Reload key
SELECT encrypt.load_key('my-master-passphrase', true);

CREATE TABLE test_verify_enc (id serial, secret encrypted_text);
INSERT INTO test_verify_enc(secret) VALUES ('verify-test-1'), ('verify-test-2');

-- Verify encryption integrity (returns status, total_rows, sampled_rows, decrypted_ok, message)
SELECT status, total_rows, sampled_rows, decrypted_ok
  FROM encrypt.verify('public', 'test_verify_enc', 'secret');

-- Test with invalid column
SELECT status, message
  FROM encrypt.verify('public', 'test_verify_enc', 'nonexistent');

-- Test with non-encrypted column
SELECT status, message
  FROM encrypt.verify('public', 'test_verify_enc', 'id');

DROP TABLE test_verify_enc;

RESET ROLE;

-- =============================================================================
-- NULL HANDLING
-- =============================================================================

CREATE TABLE test_null_handling (id serial, val encrypted_text);
INSERT INTO test_null_handling(val) VALUES (NULL);
INSERT INTO test_null_handling(val) VALUES ('not-null');
SELECT COUNT(*) FROM test_null_handling WHERE val IS NULL;
SELECT COUNT(*) FROM test_null_handling WHERE val IS NOT NULL;
DROP TABLE test_null_handling;

-- =============================================================================
-- EQUALITY AND HASH TESTS
-- =============================================================================

CREATE TABLE test_equality (id serial, val encrypted_text);
INSERT INTO test_equality(val) VALUES ('same-value');
INSERT INTO test_equality(val) VALUES ('same-value');
INSERT INTO test_equality(val) VALUES ('different-value');
SELECT COUNT(*) FROM test_equality WHERE val = 'same-value'::encrypted_text;

-- GROUP BY works on encrypted types
SELECT COUNT(*) AS distinct_count FROM (
    SELECT val FROM test_equality GROUP BY val
) sub;
DROP TABLE test_equality;

-- Hash consistency
CREATE TABLE test_hash (id serial, val encrypted_text);
INSERT INTO test_hash(val) VALUES ('hash-test');
INSERT INTO test_hash(val) VALUES ('hash-test');
SELECT (enc_hash_enctext(val) = enc_hash_enctext(val)) AS hash_consistent
FROM test_hash LIMIT 1;
SELECT COUNT(DISTINCT enc_hash_enctext(val)) AS unique_hashes FROM test_hash;
DROP TABLE test_hash;

-- =============================================================================
-- ERROR CASES
-- =============================================================================
-- Note: Binary protocol (COPY FORMAT binary, libpq binary mode) is blocked
-- at the C level with error "binary protocol is not supported for encrypted types".
-- This cannot be tested in regression because COPY TO STDOUT doesn't work in PL/pgSQL.

-- encrypt.rotate with encrypt.enable=off should fail
SET encrypt.enable = off;
DO $$
BEGIN
    BEGIN
        PERFORM encrypt.rotate('public', 'nonexistent', 'col');
        RAISE EXCEPTION 'encrypt.rotate unexpectedly succeeded with encrypt.enable=off';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM NOT LIKE '%encryption must be enabled%' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'encrypt.rotate blocked when encrypt.enable is off';
    END;
END;
$$;
SET encrypt.enable = on;

-- DEK minimum length validation
SET ROLE regress_user;
DO $$
BEGIN
    BEGIN
        PERFORM encrypt.register_key('short', 'my-master-passphrase', false);
        RAISE EXCEPTION 'encrypt.register_key unexpectedly succeeded with short key';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM NOT LIKE '%at least 16 bytes%' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'short DEK rejected as expected';
    END;
END;
$$;
RESET ROLE;

-- Wrong passphrase
SET ROLE regress_user;
DO $$
BEGIN
    BEGIN
        -- First unload to clear session
        PERFORM encrypt.unload_key();
        PERFORM encrypt.load_key('wrong-passphrase');
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM NOT LIKE '%incorrect%' AND SQLERRM NOT LIKE '%decryption%' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'wrong passphrase rejected as expected';
    END;
END;
$$;
RESET ROLE;

-- Unprivileged user cannot register keys
SET ROLE regress_unprivileged;
DO $$
BEGIN
    BEGIN
        PERFORM encrypt.register_key('unauthorized', 'passphrase');
        RAISE EXCEPTION 'encrypt.register_key unexpectedly succeeded for unprivileged user';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'encrypt.register_key denied for unprivileged user';
    END;
END;
$$;
RESET ROLE;

-- Unprivileged user cannot load keys
SET ROLE regress_unprivileged;
DO $$
BEGIN
    BEGIN
        PERFORM encrypt.load_key('any-passphrase');
        RAISE EXCEPTION 'encrypt.load_key unexpectedly succeeded for unprivileged user';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'encrypt.load_key denied for unprivileged user';
    END;
END;
$$;
RESET ROLE;

-- Empty passphrase should be rejected
SET ROLE regress_user;
DO $$
BEGIN
    BEGIN
        PERFORM encrypt.load_key('');
        RAISE EXCEPTION 'encrypt.load_key unexpectedly succeeded with empty passphrase';
    EXCEPTION
        WHEN invalid_parameter_value THEN
            RAISE NOTICE 'empty passphrase rejected as expected';
    END;
END;
$$;
RESET ROLE;

-- NULL passphrase should be rejected
SET ROLE regress_user;
DO $$
BEGIN
    BEGIN
        PERFORM encrypt.load_key(NULL);
        RAISE EXCEPTION 'encrypt.load_key unexpectedly succeeded with NULL passphrase';
    EXCEPTION
        WHEN invalid_parameter_value THEN
            RAISE NOTICE 'NULL passphrase rejected as expected';
    END;
END;
$$;
RESET ROLE;

-- batch_size <= 0 should be rejected
SET ROLE regress_user;
SELECT encrypt.load_key('my-master-passphrase', true);
DO $$
BEGIN
    BEGIN
        PERFORM encrypt.rotate('public', 'test_enc_text', 'ssn', 0);
        RAISE EXCEPTION 'encrypt.rotate unexpectedly succeeded with batch_size=0';
    EXCEPTION
        WHEN invalid_parameter_value THEN
            RAISE NOTICE 'batch_size=0 rejected as expected';
    END;
END;
$$;

DO $$
BEGIN
    BEGIN
        PERFORM encrypt.rotate('public', 'test_enc_text', 'ssn', -1);
        RAISE EXCEPTION 'encrypt.rotate unexpectedly succeeded with batch_size=-1';
    EXCEPTION
        WHEN invalid_parameter_value THEN
            RAISE NOTICE 'negative batch_size rejected as expected';
    END;
END;
$$;
RESET ROLE;

-- sample_size <= 0 should be rejected
SET ROLE regress_user;
DO $$
BEGIN
    BEGIN
        PERFORM encrypt.verify('public', 'test_enc_text', 'ssn', 0);
        RAISE EXCEPTION 'encrypt.verify unexpectedly succeeded with sample_size=0';
    EXCEPTION
        WHEN invalid_parameter_value THEN
            RAISE NOTICE 'sample_size=0 rejected as expected';
    END;
END;
$$;

DO $$
BEGIN
    BEGIN
        PERFORM encrypt.verify('public', 'test_enc_text', 'ssn', -1);
        RAISE EXCEPTION 'encrypt.verify unexpectedly succeeded with sample_size=-1';
    EXCEPTION
        WHEN invalid_parameter_value THEN
            RAISE NOTICE 'negative sample_size rejected as expected';
    END;
END;
$$;
RESET ROLE;

-- =============================================================================
-- STATUS AND INTROSPECTION
-- =============================================================================

-- Reload key for status check
SET ROLE regress_user;
SELECT encrypt.load_key('my-master-passphrase', true);
RESET ROLE;

-- Check overall status
SELECT key_loaded, active_key_version, encrypted_column_count >= 0 AS has_column_count
FROM encrypt.status();

-- List all keys with their states
SELECT key_id, key_state, algorithm FROM encrypt.keys() ORDER BY key_id;

-- =============================================================================
-- UNLOAD KEY
-- =============================================================================

SET ROLE regress_user;
SELECT encrypt.unload_key();
RESET ROLE;

-- Verify key unloaded
SELECT loaded_cipher_key_versions();

-- Status should show no key loaded
SELECT key_loaded FROM encrypt.status();

-- =============================================================================
-- CLEANUP
-- =============================================================================

DROP TABLE test_enc_text;
DROP TABLE test_enc_bytea;
DROP TABLE test_batch_rotate;
DROP TABLE test_off_mode_text;
DROP TABLE test_off_mode_bytea;
