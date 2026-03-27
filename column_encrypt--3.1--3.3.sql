/* column_encrypt--3.1--3.3.sql */

-- Upgrade script: API Simplification and Deprecation
--
-- This release introduces the 'encrypt' schema with a simplified API.
-- Old functions remain available but emit deprecation notices.
--
-- Changes:
-- 1. New 'encrypt' schema with cleaner function names
-- 2. Automatic log masking (no more disable_log/enable_log ceremony)
-- 3. Single 'column_encrypt_user' role (simplifies 3-role system)
-- 4. Deprecated: rate limiting, coverage audit, rotation jobs, audit logging
--
-- Migration: Use encrypt.* functions going forward

\echo Use "ALTER EXTENSION column_encrypt UPDATE TO '3.3'" to load this file. \quit

/*
 * =============================================================================
 * CREATE ENCRYPT SCHEMA
 * =============================================================================
 */

CREATE SCHEMA IF NOT EXISTS encrypt;

COMMENT ON SCHEMA encrypt IS
    'Simplified API for column_encrypt extension (v3.3+)';

/*
 * =============================================================================
 * SIMPLIFIED KEY MANAGEMENT API
 * =============================================================================
 */

/*
 * encrypt.register_key - Register a new data encryption key
 *
 * This is the simplified replacement for register_cipher_key().
 * Log masking is handled automatically.
 *
 * Parameters:
 *   dek        - The data encryption key (min 16 bytes, recommend 32)
 *   passphrase - Master passphrase to wrap the DEK (never stored)
 *   activate   - If true (default), make this the active key
 *
 * Returns: The assigned key ID (auto-incremented)
 */
CREATE FUNCTION encrypt.register_key(
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

    -- Input validation
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

    -- Get next key version
    SELECT COALESCE(MAX(key_version), 0) + 1 INTO v_key_id FROM cipher_key_table;

    IF v_key_id > 32767 THEN
        RAISE EXCEPTION 'maximum key version (32767) exceeded'
            USING ERRCODE = 'program_limit_exceeded';
    END IF;

    -- Lock table to prevent concurrent registration
    LOCK TABLE cipher_key_table IN EXCLUSIVE MODE;

    -- If activating, retire current active key
    IF activate THEN
        UPDATE cipher_key_table
           SET key_state = 'retired',
               state_changed_at = now()
         WHERE key_state = 'active';
    END IF;

    -- Insert new key
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

COMMENT ON FUNCTION encrypt.register_key(TEXT, TEXT, BOOLEAN) IS
    'Registers a new encryption key. Log masking is automatic. Returns key ID.';

/*
 * encrypt.load_key - Load encryption key(s) into session memory
 *
 * Simplified replacement for load_key() with automatic log masking.
 * Loads the active key by default, or all non-revoked keys if loading for rotation.
 */
CREATE FUNCTION encrypt.load_key(
    passphrase TEXT,
    all_versions BOOLEAN DEFAULT false
) RETURNS BOOLEAN
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_key_version INTEGER;
    v_count INTEGER := 0;
BEGIN
    -- Automatic log masking
    PERFORM pgstat_actv_mask();
    SET LOCAL track_activities = off;

    -- Clear existing keys
    PERFORM enc_rm_key();

    IF passphrase IS NULL THEN
        RAISE EXCEPTION 'passphrase cannot be null'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF all_versions THEN
        -- Load all non-revoked keys (for rotation workflows)
        FOR v_key_version IN
            SELECT key_version FROM cipher_key_table
            WHERE key_state <> 'revoked'
            ORDER BY key_version
        LOOP
            BEGIN
                PERFORM set_config('encrypt.key_version', v_key_version::text, true);
                PERFORM enc_store_key(
                    pgp_sym_decrypt(wrapped_key, passphrase),
                    algorithm
                )
                FROM cipher_key_table
                WHERE key_version = v_key_version;

                v_count := v_count + 1;
            EXCEPTION
                WHEN OTHERS THEN
                    PERFORM enc_rm_key();
                    RAISE EXCEPTION 'failed to decrypt key version %: incorrect passphrase', v_key_version
                        USING ERRCODE = 'invalid_password';
            END;
        END LOOP;

        -- Set current version to active key
        SELECT key_version INTO v_key_version
          FROM cipher_key_table WHERE key_state = 'active';
        IF FOUND THEN
            PERFORM set_config('encrypt.key_version', v_key_version::text, false);
        END IF;
    ELSE
        -- Load only active key
        SELECT key_version INTO v_key_version
          FROM cipher_key_table WHERE key_state = 'active';

        IF NOT FOUND THEN
            RETURN false;
        END IF;

        BEGIN
            PERFORM set_config('encrypt.key_version', v_key_version::text, false);
            PERFORM enc_store_key(
                pgp_sym_decrypt(wrapped_key, passphrase),
                algorithm
            )
            FROM cipher_key_table
            WHERE key_state = 'active';

            -- Update usage statistics
            UPDATE cipher_key_table
               SET last_used_at = now(),
                   use_count = use_count + 1
             WHERE key_version = v_key_version;

            v_count := 1;
        EXCEPTION
            WHEN OTHERS THEN
                PERFORM enc_rm_key();
                RAISE EXCEPTION 'incorrect passphrase'
                    USING ERRCODE = 'invalid_password';
        END;
    END IF;

    RETURN v_count > 0;
END;
$$;

COMMENT ON FUNCTION encrypt.load_key(TEXT, BOOLEAN) IS
    'Loads encryption key(s) into session. Use all_versions=true for rotation workflows.';

/*
 * encrypt.unload_key - Clear all keys from session memory
 */
CREATE FUNCTION encrypt.unload_key() RETURNS VOID
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    PERFORM enc_rm_key();
END;
$$;

COMMENT ON FUNCTION encrypt.unload_key() IS
    'Removes all encryption keys from session memory (secure wipe).';

/*
 * encrypt.activate_key - Make a key version the active key
 */
CREATE FUNCTION encrypt.activate_key(key_id INTEGER) RETURNS BOOLEAN
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

    -- Check if key is expired
    IF EXISTS (
        SELECT 1 FROM cipher_key_table
        WHERE key_version = key_id
          AND expires_at IS NOT NULL
          AND expires_at <= now()
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

COMMENT ON FUNCTION encrypt.activate_key(INTEGER) IS
    'Makes the specified key version the active key for new encryptions.';

/*
 * encrypt.revoke_key - Revoke a key version (prevents loading)
 */
CREATE FUNCTION encrypt.revoke_key(key_id INTEGER) RETURNS BOOLEAN
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    UPDATE cipher_key_table
       SET key_state = 'revoked',
           state_changed_at = now()
     WHERE key_version = key_id;

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION encrypt.revoke_key(INTEGER) IS
    'Revokes a key version, preventing it from being loaded.';

/*
 * =============================================================================
 * SIMPLIFIED OPERATIONS
 * =============================================================================
 */

/*
 * encrypt.rotate - Re-encrypt column data with current active key
 */
CREATE FUNCTION encrypt.rotate(
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
        RAISE EXCEPTION 'encryption must be enabled (SET encrypt.enable = on)'
            USING ERRCODE = 'feature_not_supported';
    END IF;

    -- Validate inputs
    IF schema_name !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       table_name  !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       column_name !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
        RAISE EXCEPTION 'invalid identifier'
            USING ERRCODE = 'invalid_name';
    END IF;

    -- Get column type
    SELECT format_type(a.atttypid, a.atttypmod)
      INTO v_col_type
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = schema_name
       AND c.relname = table_name
       AND a.attname = column_name
       AND a.attnum > 0
       AND NOT a.attisdropped;

    IF v_col_type IS NULL THEN
        RAISE EXCEPTION 'column %.%.% not found', schema_name, table_name, column_name
            USING ERRCODE = 'undefined_column';
    END IF;

    IF v_col_type NOT IN ('encrypted_text', 'encrypted_bytea') THEN
        RAISE EXCEPTION 'column is not an encrypted type'
            USING ERRCODE = 'wrong_object_type';
    END IF;

    -- Process in batches
    LOOP
        v_sql := format(
            'WITH batch AS (
                SELECT ctid
                  FROM %I.%I
                 WHERE %I IS NOT NULL
                   AND enc_key_version(%I) <> current_setting(''encrypt.key_version'')::integer
                 LIMIT %s
             )
             UPDATE %I.%I AS t
                SET %I = t.%I::text::%s
               FROM batch
              WHERE t.ctid = batch.ctid',
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

COMMENT ON FUNCTION encrypt.rotate(TEXT, TEXT, TEXT, INTEGER) IS
    'Re-encrypts all data in the column with the current active key.';

/*
 * encrypt.verify - Verify encrypted column can be decrypted
 */
CREATE FUNCTION encrypt.verify(
    schema_name TEXT,
    table_name TEXT,
    column_name TEXT,
    sample_size INTEGER DEFAULT 100
) RETURNS TABLE(
    status TEXT,
    total_rows BIGINT,
    sampled_rows BIGINT,
    decrypted_ok BIGINT,
    message TEXT
)
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
    -- Get column type
    SELECT format_type(a.atttypid, a.atttypmod)
      INTO v_col_type
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = schema_name
       AND c.relname = table_name
       AND a.attname = column_name;

    IF v_col_type IS NULL THEN
        status := 'error';
        message := 'column not found';
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_col_type NOT IN ('encrypted_text', 'encrypted_bytea') THEN
        status := 'error';
        message := 'not an encrypted column';
        RETURN NEXT;
        RETURN;
    END IF;

    -- Count total rows
    EXECUTE format('SELECT count(*) FROM %I.%I WHERE %I IS NOT NULL',
        schema_name, table_name, column_name) INTO v_total;

    -- Try to decrypt sample
    FOR rec IN EXECUTE format(
        'SELECT ctid FROM %I.%I WHERE %I IS NOT NULL LIMIT %s',
        schema_name, table_name, column_name, sample_size
    ) LOOP
        v_sampled := v_sampled + 1;
        BEGIN
            EXECUTE format('SELECT %I::text FROM %I.%I WHERE ctid = $1',
                column_name, schema_name, table_name) USING rec.ctid;
            v_ok := v_ok + 1;
        EXCEPTION WHEN OTHERS THEN
            NULL; -- Count as failure
        END;
    END LOOP;

    total_rows := v_total;
    sampled_rows := v_sampled;
    decrypted_ok := v_ok;

    IF v_sampled = 0 THEN
        status := 'ok';
        message := 'no data to verify';
    ELSIF v_ok = v_sampled THEN
        status := 'ok';
        message := format('all %s sampled rows decrypted successfully', v_sampled);
    ELSE
        status := 'error';
        message := format('%s of %s rows failed to decrypt', v_sampled - v_ok, v_sampled);
    END IF;

    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION encrypt.verify(TEXT, TEXT, TEXT, INTEGER) IS
    'Verifies that encrypted column data can be decrypted with loaded keys.';

/*
 * =============================================================================
 * SIMPLIFIED METADATA
 * =============================================================================
 */

/*
 * encrypt.keys - View registered keys
 */
CREATE FUNCTION encrypt.keys() RETURNS TABLE(
    key_id INTEGER,
    key_state TEXT,
    algorithm TEXT,
    created_at TIMESTAMPTZ,
    last_used TIMESTAMPTZ,
    use_count BIGINT
)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO public
AS $$
    SELECT key_version, key_state, algorithm, created_at, last_used_at, use_count
      FROM cipher_key_table
     ORDER BY key_version;
$$;

COMMENT ON FUNCTION encrypt.keys() IS
    'Lists all registered encryption keys with their state and usage.';

/*
 * encrypt.status - Quick status check
 */
CREATE FUNCTION encrypt.status() RETURNS TABLE(
    key_loaded BOOLEAN,
    active_key_version INTEGER,
    session_keys INTEGER[],
    encrypted_column_count INTEGER
)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_loaded INTEGER[];
    v_active INTEGER;
    v_columns INTEGER;
BEGIN
    v_loaded := loaded_cipher_key_versions();

    SELECT key_version INTO v_active
      FROM cipher_key_table WHERE key_state = 'active';

    SELECT count(*) INTO v_columns
      FROM pg_attribute a
      JOIN pg_type t ON t.oid = a.atttypid
      JOIN pg_class c ON c.oid = a.attrelid
     WHERE t.typname IN ('encrypted_text', 'encrypted_bytea')
       AND c.relkind = 'r'
       AND a.attnum > 0
       AND NOT a.attisdropped;

    key_loaded := array_length(v_loaded, 1) IS NOT NULL;
    active_key_version := v_active;
    session_keys := v_loaded;
    encrypted_column_count := v_columns;

    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION encrypt.status() IS
    'Quick status check: key loaded, active key, encrypted columns count.';

/*
 * encrypt.blind_index - Create searchable blind index
 */
CREATE FUNCTION encrypt.blind_index(value TEXT, hmac_key TEXT) RETURNS TEXT
    LANGUAGE sql IMMUTABLE STRICT
AS $$
    SELECT encode(
        hmac(convert_to(value, 'UTF8'), convert_to(hmac_key, 'UTF8'), 'sha256'),
        'hex'
    );
$$;

COMMENT ON FUNCTION encrypt.blind_index(TEXT, TEXT) IS
    'Creates HMAC-SHA256 blind index for searchable encryption.';

/*
 * =============================================================================
 * SIMPLIFIED ROLE
 * =============================================================================
 */

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'column_encrypt_user') THEN
        EXECUTE 'CREATE ROLE column_encrypt_user NOLOGIN';
    END IF;
END;
$$;

COMMENT ON ROLE column_encrypt_user IS
    'Unified role for column_encrypt users (replaces admin/runtime/reader roles)';

-- Grant new API to unified role
GRANT USAGE ON SCHEMA encrypt TO column_encrypt_user;
GRANT EXECUTE ON FUNCTION encrypt.register_key(TEXT, TEXT, BOOLEAN) TO column_encrypt_user;
GRANT EXECUTE ON FUNCTION encrypt.load_key(TEXT, BOOLEAN) TO column_encrypt_user;
GRANT EXECUTE ON FUNCTION encrypt.unload_key() TO column_encrypt_user;
GRANT EXECUTE ON FUNCTION encrypt.activate_key(INTEGER) TO column_encrypt_user;
GRANT EXECUTE ON FUNCTION encrypt.revoke_key(INTEGER) TO column_encrypt_user;
GRANT EXECUTE ON FUNCTION encrypt.rotate(TEXT, TEXT, TEXT, INTEGER) TO column_encrypt_user;
GRANT EXECUTE ON FUNCTION encrypt.verify(TEXT, TEXT, TEXT, INTEGER) TO column_encrypt_user;
GRANT EXECUTE ON FUNCTION encrypt.keys() TO column_encrypt_user;
GRANT EXECUTE ON FUNCTION encrypt.status() TO column_encrypt_user;
GRANT EXECUTE ON FUNCTION encrypt.blind_index(TEXT, TEXT) TO column_encrypt_user;

-- Also grant to existing roles for compatibility
GRANT USAGE ON SCHEMA encrypt TO column_encrypt_admin;
GRANT USAGE ON SCHEMA encrypt TO column_encrypt_runtime;
GRANT USAGE ON SCHEMA encrypt TO column_encrypt_reader;

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA encrypt TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION encrypt.load_key(TEXT, BOOLEAN) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION encrypt.unload_key() TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION encrypt.keys() TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION encrypt.status() TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION encrypt.blind_index(TEXT, TEXT) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION encrypt.keys() TO column_encrypt_reader;
GRANT EXECUTE ON FUNCTION encrypt.status() TO column_encrypt_reader;

/*
 * =============================================================================
 * DEPRECATION NOTICES
 * =============================================================================
 * The following functions are deprecated and will be removed in v4.0.
 * Use the encrypt.* equivalents instead.
 */

-- Wrap old functions to emit deprecation notices

CREATE OR REPLACE FUNCTION cipher_key_disable_log() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    RAISE NOTICE 'DEPRECATED: cipher_key_disable_log() is no longer needed. encrypt.* functions handle log masking automatically.';
    SET track_activities = off;
    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION cipher_key_enable_log() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    RAISE NOTICE 'DEPRECATED: cipher_key_enable_log() is no longer needed. encrypt.* functions handle log masking automatically.';
    SET track_activities = DEFAULT;
    RETURN TRUE;
END;
$$;

-- Add deprecation comment
COMMENT ON FUNCTION cipher_key_disable_log() IS
    'DEPRECATED in v3.3. Use encrypt.* functions which handle log masking automatically.';
COMMENT ON FUNCTION cipher_key_enable_log() IS
    'DEPRECATED in v3.3. Use encrypt.* functions which handle log masking automatically.';
COMMENT ON FUNCTION register_cipher_key(text, text, text) IS
    'DEPRECATED in v3.3. Use encrypt.register_key() instead.';
COMMENT ON FUNCTION register_cipher_key(text, text, text, integer, boolean, timestamptz, text) IS
    'DEPRECATED in v3.3. Use encrypt.register_key() instead.';
COMMENT ON FUNCTION load_key(text) IS
    'DEPRECATED in v3.3. Use encrypt.load_key() instead.';
COMMENT ON FUNCTION load_key_by_version(text, integer) IS
    'DEPRECATED in v3.3. Use encrypt.load_key(passphrase, all_versions => true) instead.';
COMMENT ON FUNCTION rm_key_details() IS
    'DEPRECATED in v3.3. Use encrypt.unload_key() instead.';
COMMENT ON FUNCTION activate_cipher_key(integer) IS
    'DEPRECATED in v3.3. Use encrypt.activate_key() instead.';
COMMENT ON FUNCTION revoke_cipher_key(integer) IS
    'DEPRECATED in v3.3. Use encrypt.revoke_key() instead.';
COMMENT ON FUNCTION cipher_key_versions() IS
    'DEPRECATED in v3.3. Use encrypt.keys() instead.';
COMMENT ON FUNCTION cipher_key_reencrypt_data(text, text, text) IS
    'DEPRECATED in v3.3. Use encrypt.rotate() instead.';
COMMENT ON FUNCTION cipher_key_reencrypt_data_batch(text, text, text, integer) IS
    'DEPRECATED in v3.3. Use encrypt.rotate() instead.';
COMMENT ON FUNCTION cipher_verify_column_encryption(text, text, text, integer) IS
    'DEPRECATED in v3.3. Use encrypt.verify() instead.';

/*
 * =============================================================================
 * FEATURES MARKED FOR REMOVAL IN v4.0
 * =============================================================================
 * The following features are out of scope for an encryption extension
 * and will be removed in v4.0:
 *
 * - cipher_key_audit_log table and related functions (use pg_audit instead)
 * - Rate limiting functions (use application-level or fail2ban)
 * - Coverage audit functions (use separate compliance tool)
 * - Rotation job scheduler (use pg_cron for scheduling)
 * - Monitoring/metrics functions (query pg_catalog directly)
 */

-- Mark for removal
COMMENT ON TABLE cipher_key_audit_log IS
    'DEPRECATED in v3.3. Will be removed in v4.0. Use pg_audit extension instead.';

COMMENT ON FUNCTION cipher_key_check_expired() IS
    'DEPRECATED in v3.3. Will be removed in v4.0. Query encrypt.keys() directly.';
COMMENT ON FUNCTION cipher_key_audit_log_view(integer, integer) IS
    'DEPRECATED in v3.3. Will be removed in v4.0. Use pg_audit extension.';
COMMENT ON FUNCTION cipher_key_logical_replication_check(text, text) IS
    'DEPRECATED in v3.3. Will be removed in v4.0. See documentation for replication guidance.';
COMMENT ON FUNCTION is_key_loaded() IS
    'DEPRECATED in v3.3. Use encrypt.status() instead.';
COMMENT ON FUNCTION loaded_cipher_key_versions() IS
    'DEPRECATED in v3.3. Use encrypt.status() instead.';
