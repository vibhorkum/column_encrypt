/* column_encrypt--3.3--4.0.sql */

-- Upgrade script: Clean API Release
--
-- v4.0 removes all deprecated features and provides only the simplified API.
--
-- REMOVED in v4.0:
-- - cipher_key_disable_log() / cipher_key_enable_log()
-- - register_cipher_key() (use encrypt.register_key)
-- - load_key() / load_key_by_version() (use encrypt.load_key)
-- - rm_key_details() (use encrypt.unload_key)
-- - activate_cipher_key() / revoke_cipher_key()
-- - cipher_key_versions() (use encrypt.keys)
-- - cipher_key_reencrypt_data*() (use encrypt.rotate)
-- - cipher_verify_column_encryption() (use encrypt.verify)
-- - cipher_key_audit_log table and functions
-- - Rate limiting tables and functions
-- - Coverage audit functions
-- - Rotation job scheduler
-- - Monitoring/metrics functions
-- - 3-role system (replaced by column_encrypt_user)
--
-- MIGRATION: Update your code to use encrypt.* functions before upgrading.

\echo Use "ALTER EXTENSION column_encrypt UPDATE TO '4.0'" to load this file. \quit

/*
 * =============================================================================
 * REMOVE DEPRECATED FUNCTIONS
 * =============================================================================
 */

-- Key management (old API)
DROP FUNCTION IF EXISTS cipher_key_disable_log();
DROP FUNCTION IF EXISTS cipher_key_enable_log();
DROP FUNCTION IF EXISTS register_cipher_key(text, text, text);
DROP FUNCTION IF EXISTS register_cipher_key(text, text, text, integer, boolean, timestamptz, text);
DROP FUNCTION IF EXISTS load_key(text);
DROP FUNCTION IF EXISTS load_key_by_version(text, integer);
DROP FUNCTION IF EXISTS rm_key_details();
DROP FUNCTION IF EXISTS activate_cipher_key(integer);
DROP FUNCTION IF EXISTS revoke_cipher_key(integer);
DROP FUNCTION IF EXISTS cipher_key_versions();
DROP FUNCTION IF EXISTS cipher_key_reencrypt_data(text, text, text);
DROP FUNCTION IF EXISTS cipher_key_reencrypt_data(text, text, text, integer);
DROP FUNCTION IF EXISTS cipher_key_reencrypt_data_batch(text, text, text, integer);
DROP FUNCTION IF EXISTS cipher_verify_column_encryption(text, text, text, integer);

-- Audit logging
DROP FUNCTION IF EXISTS cipher_key_audit_log_view(integer, integer);
DROP FUNCTION IF EXISTS cipher_key_check_expired();
DROP TABLE IF EXISTS cipher_key_audit_log;

-- Rate limiting (if exists from v3.2 or manual install)
DROP FUNCTION IF EXISTS cipher_key_is_locked_out(name);
DROP FUNCTION IF EXISTS cipher_key_record_failed_attempt(name);
DROP FUNCTION IF EXISTS cipher_key_clear_failed_attempts(name);
DROP FUNCTION IF EXISTS cipher_key_unlock_user(name);
DROP FUNCTION IF EXISTS cipher_key_lockout_status();
DROP FUNCTION IF EXISTS cipher_key_rate_limit_config();
DROP TABLE IF EXISTS cipher_key_failed_attempts;

-- Coverage audit
DROP FUNCTION IF EXISTS cipher_coverage_audit(text);
DROP FUNCTION IF EXISTS cipher_coverage_summary(text);

-- Rotation job scheduler
DROP FUNCTION IF EXISTS cipher_start_rotation_job(text, text, text, integer, integer, integer);
DROP FUNCTION IF EXISTS cipher_process_rotation_batch(bigint);
DROP FUNCTION IF EXISTS cipher_run_rotation_job(bigint);
DROP FUNCTION IF EXISTS cipher_pause_rotation_job(bigint);
DROP FUNCTION IF EXISTS cipher_resume_rotation_job(bigint);
DROP FUNCTION IF EXISTS cipher_cancel_rotation_job(bigint);
DROP FUNCTION IF EXISTS cipher_rotation_progress();
DROP TABLE IF EXISTS cipher_rotation_jobs;

-- Monitoring/metrics
DROP FUNCTION IF EXISTS cipher_encryption_stats();
DROP FUNCTION IF EXISTS cipher_key_usage_stats();
DROP FUNCTION IF EXISTS cipher_metrics();
DROP FUNCTION IF EXISTS is_key_loaded();
DROP FUNCTION IF EXISTS cipher_dump_warnings(text);
DROP FUNCTION IF EXISTS cipher_pre_dump_check(text, boolean);
DROP FUNCTION IF EXISTS cipher_guc_reference();
DROP FUNCTION IF EXISTS cipher_status();

-- Replication check
DROP FUNCTION IF EXISTS cipher_key_logical_replication_check(text, text);

-- Internal/legacy functions that were exposed
DROP FUNCTION IF EXISTS enc_store_prv_key(text, text);
DROP FUNCTION IF EXISTS enc_rm_prv_key();

/*
 * =============================================================================
 * CLEAN UP ROLES
 * =============================================================================
 * Keep column_encrypt_user as the canonical role.
 * Old roles are NOT dropped (would break existing grants) but revoked new permissions.
 */

-- Ensure new role exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'column_encrypt_user') THEN
        EXECUTE 'CREATE ROLE column_encrypt_user NOLOGIN';
    END IF;
END;
$$;

/*
 * =============================================================================
 * REVOKE PUBLIC EXECUTION ON INTERNAL FUNCTIONS
 * =============================================================================
 */

REVOKE EXECUTE ON FUNCTION enc_store_key(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_rm_key() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pgstat_actv_mask() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION loaded_cipher_key_versions() FROM PUBLIC;

/*
 * =============================================================================
 * REFRESH ENCRYPT.* FUNCTION BODIES TO V4.0 DEFINITIONS
 * =============================================================================
 * Ensures upgraded databases have identical function bodies to fresh installs.
 */

CREATE OR REPLACE FUNCTION encrypt.register_key(
    dek TEXT,
    passphrase TEXT,
    activate BOOLEAN DEFAULT true
) RETURNS INTEGER
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_key_id INTEGER;
BEGIN
    -- Automatic log masking
    PERFORM pgstat_actv_mask();
    SET LOCAL track_activities = off;

    -- Validation
    IF dek IS NULL OR dek = '' THEN
        RAISE EXCEPTION 'encryption key cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF octet_length(dek) < 16 THEN
        RAISE EXCEPTION 'encryption key must be at least 16 bytes'
            USING ERRCODE = 'invalid_parameter_value',
            HINT = 'Use a 32-byte key for AES-256 security';
    END IF;

    IF passphrase IS NULL OR passphrase = '' THEN
        RAISE EXCEPTION 'passphrase cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Lock first to prevent concurrent registration race
    LOCK TABLE cipher_key_table IN EXCLUSIVE MODE;

    -- Get next key ID (after lock to prevent race condition)
    SELECT COALESCE(MAX(key_version), 0) + 1 INTO v_key_id FROM cipher_key_table;

    IF v_key_id > 32767 THEN
        RAISE EXCEPTION 'maximum key version (32767) exceeded'
            USING ERRCODE = 'program_limit_exceeded';
    END IF;

    IF activate THEN
        UPDATE cipher_key_table
           SET key_state = 'retired', state_changed_at = now()
         WHERE key_state = 'active';
    END IF;

    INSERT INTO cipher_key_table(key_version, wrapped_key, algorithm, key_state, state_changed_at)
    VALUES(
        v_key_id,
        pgp_sym_encrypt(dek, passphrase, 'cipher-algo=aes256, s2k-mode=3'),
        'aes',
        CASE WHEN activate THEN 'active' ELSE 'pending' END,
        now()
    );

    RETURN v_key_id;
END;
$$;

CREATE OR REPLACE FUNCTION encrypt.load_key(
    passphrase TEXT,
    all_versions BOOLEAN DEFAULT false
) RETURNS BOOLEAN
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_key_version INTEGER;
    v_count INTEGER := 0;
    v_prev_key_version TEXT;
BEGIN
    PERFORM pgstat_actv_mask();
    SET LOCAL track_activities = off;

    -- Save previous GUC value for restore on failure
    v_prev_key_version := current_setting('encrypt.key_version', true);

    PERFORM enc_rm_key();

    IF passphrase IS NULL OR passphrase = '' THEN
        RAISE EXCEPTION 'passphrase cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF all_versions THEN
        FOR v_key_version IN
            SELECT key_version FROM cipher_key_table
            WHERE key_state <> 'revoked' ORDER BY key_version
        LOOP
            BEGIN
                PERFORM set_config('encrypt.key_version', v_key_version::text, true);
                PERFORM enc_store_key(
                    pgp_sym_decrypt(wrapped_key, passphrase), algorithm
                ) FROM cipher_key_table WHERE key_version = v_key_version;
                v_count := v_count + 1;
            EXCEPTION WHEN OTHERS THEN
                PERFORM enc_rm_key();
                -- Restore previous GUC value
                IF v_prev_key_version IS NOT NULL AND v_prev_key_version <> '' THEN
                    PERFORM set_config('encrypt.key_version', v_prev_key_version, false);
                ELSE
                    PERFORM set_config('encrypt.key_version', '', false);
                END IF;
                RAISE EXCEPTION 'failed to decrypt key version %', v_key_version
                    USING ERRCODE = 'invalid_password';
            END;
        END LOOP;

        SELECT key_version INTO v_key_version
          FROM cipher_key_table WHERE key_state = 'active';
        IF FOUND THEN
            PERFORM set_config('encrypt.key_version', v_key_version::text, false);
        END IF;
    ELSE
        SELECT key_version INTO v_key_version
          FROM cipher_key_table WHERE key_state = 'active';

        IF NOT FOUND THEN
            RETURN false;
        END IF;

        BEGIN
            PERFORM set_config('encrypt.key_version', v_key_version::text, false);
            PERFORM enc_store_key(
                pgp_sym_decrypt(wrapped_key, passphrase), algorithm
            ) FROM cipher_key_table WHERE key_state = 'active';

            UPDATE cipher_key_table
               SET last_used_at = now(), use_count = use_count + 1
             WHERE key_version = v_key_version;
            v_count := 1;
        EXCEPTION WHEN OTHERS THEN
            PERFORM enc_rm_key();
            -- Restore previous GUC value
            IF v_prev_key_version IS NOT NULL AND v_prev_key_version <> '' THEN
                PERFORM set_config('encrypt.key_version', v_prev_key_version, false);
            ELSE
                PERFORM set_config('encrypt.key_version', '', false);
            END IF;
            RAISE EXCEPTION 'incorrect passphrase'
                USING ERRCODE = 'invalid_password';
        END;
    END IF;

    RETURN v_count > 0;
END;
$$;

CREATE OR REPLACE FUNCTION encrypt.unload_key() RETURNS VOID
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    PERFORM enc_rm_key();
END;
$$;

CREATE OR REPLACE FUNCTION encrypt.activate_key(key_id INTEGER) RETURNS BOOLEAN
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM cipher_key_table
        WHERE key_version = key_id AND key_state <> 'revoked'
    ) THEN
        RETURN false;
    END IF;

    IF EXISTS (
        SELECT 1 FROM cipher_key_table
        WHERE key_version = key_id AND expires_at IS NOT NULL AND expires_at <= now()
    ) THEN
        RAISE EXCEPTION 'cannot activate expired key'
            USING ERRCODE = 'data_exception';
    END IF;

    UPDATE cipher_key_table
       SET key_state = CASE
               WHEN key_version = key_id THEN 'active'
               WHEN key_state = 'active' THEN 'retired'
               ELSE key_state
           END,
           state_changed_at = CASE
               WHEN key_version = key_id OR key_state = 'active' THEN now()
               ELSE state_changed_at
           END
     WHERE key_state <> 'revoked';

    PERFORM set_config('encrypt.key_version', key_id::text, false);
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION encrypt.revoke_key(key_id INTEGER) RETURNS BOOLEAN
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    UPDATE cipher_key_table
       SET key_state = 'revoked', state_changed_at = now()
     WHERE key_version = key_id;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION encrypt.rotate(
    schema_name TEXT,
    table_name TEXT,
    column_name TEXT,
    batch_size INTEGER DEFAULT 10000
) RETURNS BIGINT
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_col_type TEXT;
    v_sql TEXT;
    v_count BIGINT := 0;
    v_batch BIGINT;
BEGIN
    IF current_setting('encrypt.enable', true) <> 'on' THEN
        RAISE EXCEPTION 'encryption must be enabled'
            USING ERRCODE = 'feature_not_supported';
    END IF;

    IF batch_size IS NULL OR batch_size <= 0 THEN
        RAISE EXCEPTION 'batch_size must be greater than 0'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF schema_name !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       table_name  !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       column_name !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
        RAISE EXCEPTION 'invalid identifier' USING ERRCODE = 'invalid_name';
    END IF;

    SELECT format_type(a.atttypid, a.atttypmod) INTO v_col_type
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = schema_name AND c.relname = table_name
       AND a.attname = column_name AND a.attnum > 0 AND NOT a.attisdropped;

    IF v_col_type IS NULL THEN
        RAISE EXCEPTION 'column not found' USING ERRCODE = 'undefined_column';
    END IF;

    IF v_col_type NOT IN ('encrypted_text', 'encrypted_bytea') THEN
        RAISE EXCEPTION 'not an encrypted column' USING ERRCODE = 'wrong_object_type';
    END IF;

    LOOP
        v_sql := format(
            'WITH batch AS (
                SELECT ctid FROM %I.%I
                WHERE %I IS NOT NULL
                  AND enc_key_version(%I) <> current_setting(''encrypt.key_version'')::integer
                LIMIT %s
            )
            UPDATE %I.%I AS t SET %I = t.%I::text::%s
            FROM batch WHERE t.ctid = batch.ctid',
            schema_name, table_name, column_name, column_name, batch_size,
            schema_name, table_name, column_name, column_name, v_col_type
        );
        EXECUTE v_sql;
        GET DIAGNOSTICS v_batch = ROW_COUNT;
        EXIT WHEN v_batch = 0;
        v_count := v_count + v_batch;
    END LOOP;

    RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION encrypt.verify(
    schema_name TEXT,
    table_name TEXT,
    column_name TEXT,
    sample_size INTEGER DEFAULT 100
) RETURNS TABLE(status TEXT, total_rows BIGINT, sampled_rows BIGINT, decrypted_ok BIGINT, message TEXT)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_total BIGINT;
    v_sampled BIGINT := 0;
    v_ok BIGINT := 0;
    v_col_type TEXT;
    rec RECORD;
BEGIN
    IF sample_size IS NULL OR sample_size <= 0 THEN
        RAISE EXCEPTION 'sample_size must be greater than 0'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    SELECT format_type(a.atttypid, a.atttypmod) INTO v_col_type
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = schema_name AND c.relname = table_name
       AND a.attname = column_name AND a.attnum > 0 AND NOT a.attisdropped;

    IF v_col_type IS NULL THEN
        status := 'error'; message := 'column not found'; RETURN NEXT; RETURN;
    END IF;

    IF v_col_type NOT IN ('encrypted_text', 'encrypted_bytea') THEN
        status := 'error'; message := 'not an encrypted column'; RETURN NEXT; RETURN;
    END IF;

    EXECUTE format('SELECT count(*) FROM %I.%I WHERE %I IS NOT NULL',
        schema_name, table_name, column_name) INTO v_total;

    FOR rec IN EXECUTE format(
        'SELECT ctid FROM %I.%I WHERE %I IS NOT NULL LIMIT %s',
        schema_name, table_name, column_name, sample_size
    ) LOOP
        v_sampled := v_sampled + 1;
        BEGIN
            EXECUTE format('SELECT %I::text FROM %I.%I WHERE ctid = $1',
                column_name, schema_name, table_name) USING rec.ctid;
            v_ok := v_ok + 1;
        EXCEPTION WHEN OTHERS THEN NULL;
        END;
    END LOOP;

    total_rows := v_total;
    sampled_rows := v_sampled;
    decrypted_ok := v_ok;

    IF v_sampled = 0 THEN
        status := 'ok'; message := 'no data to verify';
    ELSIF v_ok = v_sampled THEN
        status := 'ok'; message := format('all %s sampled rows decrypted', v_sampled);
    ELSE
        status := 'error'; message := format('%s of %s rows failed', v_sampled - v_ok, v_sampled);
    END IF;
    RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION encrypt.keys() RETURNS TABLE(
    key_id INTEGER, key_state TEXT, algorithm TEXT,
    created_at TIMESTAMPTZ, last_used TIMESTAMPTZ, use_count BIGINT
)
    LANGUAGE sql SECURITY DEFINER SET search_path TO public
AS $$
    SELECT key_version, key_state, algorithm, created_at, last_used_at, use_count
      FROM cipher_key_table ORDER BY key_version;
$$;

CREATE OR REPLACE FUNCTION encrypt.status() RETURNS TABLE(
    key_loaded BOOLEAN, active_key_version INTEGER,
    session_keys INTEGER[], encrypted_column_count INTEGER
)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path TO public
AS $$
DECLARE
    v_loaded INTEGER[];
    v_active INTEGER;
    v_columns INTEGER;
BEGIN
    v_loaded := loaded_cipher_key_versions();
    SELECT key_version INTO v_active FROM cipher_key_table WHERE key_state = 'active';
    SELECT count(*) INTO v_columns
      FROM pg_attribute a
      JOIN pg_type t ON t.oid = a.atttypid
      JOIN pg_class c ON c.oid = a.attrelid
     WHERE t.typname IN ('encrypted_text', 'encrypted_bytea')
       AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped;

    key_loaded := array_length(v_loaded, 1) IS NOT NULL;
    active_key_version := v_active;
    session_keys := v_loaded;
    encrypted_column_count := v_columns;
    RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION encrypt.blind_index(value TEXT, hmac_key TEXT) RETURNS TEXT
    LANGUAGE sql IMMUTABLE STRICT
AS $$
    SELECT encode(hmac(convert_to(value, 'UTF8'), convert_to(hmac_key, 'UTF8'), 'sha256'), 'hex');
$$;

/*
 * =============================================================================
 * UPDATE COMMENTS
 * =============================================================================
 */

COMMENT ON SCHEMA encrypt IS
    'Column encryption API - register keys, load, rotate, verify';

COMMENT ON TYPE encrypted_text IS
    'Encrypted text type. Use encrypt.load_key() before accessing data.';

COMMENT ON TYPE encrypted_bytea IS
    'Encrypted bytea type. Use encrypt.load_key() before accessing data.';

COMMENT ON TABLE cipher_key_table IS
    'Wrapped encryption keys. Access via encrypt.keys() function.';

-- Remove deprecation comments since functions are gone
COMMENT ON FUNCTION encrypt.register_key(TEXT, TEXT, BOOLEAN) IS
    'Registers a new encryption key. Returns the assigned key ID.';

COMMENT ON FUNCTION encrypt.load_key(TEXT, BOOLEAN) IS
    'Loads encryption key(s) into session memory. Use all_versions=true for rotation.';

COMMENT ON FUNCTION encrypt.unload_key() IS
    'Clears all encryption keys from session memory.';

COMMENT ON FUNCTION encrypt.activate_key(INTEGER) IS
    'Makes the specified key version the active key for new encryptions.';

COMMENT ON FUNCTION encrypt.revoke_key(INTEGER) IS
    'Revokes a key version, preventing it from being loaded.';

COMMENT ON FUNCTION encrypt.rotate(TEXT, TEXT, TEXT, INTEGER) IS
    'Re-encrypts column data with the current active key. Returns row count.';

COMMENT ON FUNCTION encrypt.verify(TEXT, TEXT, TEXT, INTEGER) IS
    'Verifies encrypted data can be decrypted with loaded keys.';

COMMENT ON FUNCTION encrypt.keys() IS
    'Lists all registered encryption keys with state and usage.';

COMMENT ON FUNCTION encrypt.status() IS
    'Returns current encryption status: key loaded, active key, column count.';

COMMENT ON FUNCTION encrypt.blind_index(TEXT, TEXT) IS
    'Creates HMAC-SHA256 blind index for searchable encryption.';
