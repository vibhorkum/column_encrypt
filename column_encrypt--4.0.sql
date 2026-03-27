/* share/extension/column_encrypt--4.0.sql */

-- Version 4.0: Simplified Column Encryption Extension
--
-- This is the clean, simplified API for transparent column-level encryption.
--
-- Usage:
--   1. CREATE EXTENSION column_encrypt;
--   2. SELECT encrypt.register_key('your-32-byte-key', 'passphrase');
--   3. SELECT encrypt.load_key('passphrase');
--   4. CREATE TABLE t (data encrypted_text);
--   5. INSERT/SELECT works transparently
--
-- Key rotation:
--   1. SELECT encrypt.register_key('new-key', 'passphrase');
--   2. SELECT encrypt.load_key('passphrase', all_versions => true);
--   3. SELECT encrypt.activate_key(2);
--   4. SELECT encrypt.rotate('public', 'tablename', 'column');

\echo Use "CREATE EXTENSION column_encrypt" to load this file. \quit

SET check_function_bodies TO off;

/*
 * =============================================================================
 * ENCRYPTED TYPES
 * =============================================================================
 */

CREATE TYPE encrypted_bytea;
CREATE TYPE encrypted_text;

-- Type I/O functions (C layer)
CREATE FUNCTION col_enc_bytea_in(cstring) RETURNS encrypted_bytea
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'col_enc_bytea_in';

CREATE FUNCTION col_enc_bytea_out(encrypted_bytea) RETURNS cstring
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'col_enc_bytea_out';

CREATE FUNCTION col_enc_recv_bytea(internal) RETURNS encrypted_bytea
    LANGUAGE c IMMUTABLE STRICT AS 'column_encrypt', 'col_enc_recv';

CREATE FUNCTION col_enc_send_bytea(encrypted_bytea) RETURNS bytea
    LANGUAGE c IMMUTABLE STRICT AS 'column_encrypt', 'col_enc_send';

CREATE TYPE encrypted_bytea (
    INTERNALLENGTH = variable,
    INPUT = col_enc_bytea_in,
    OUTPUT = col_enc_bytea_out,
    RECEIVE = col_enc_recv_bytea,
    SEND = col_enc_send_bytea,
    ALIGNMENT = int4,
    STORAGE = extended
);

CREATE FUNCTION col_enc_text_in(cstring) RETURNS encrypted_text
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'col_enc_text_in';

CREATE FUNCTION col_enc_text_out(encrypted_text) RETURNS cstring
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'col_enc_text_out';

CREATE FUNCTION col_enc_recv_text(internal) RETURNS encrypted_text
    LANGUAGE c IMMUTABLE STRICT AS 'column_encrypt', 'col_enc_recv';

CREATE FUNCTION col_enc_send_text(encrypted_text) RETURNS bytea
    LANGUAGE c IMMUTABLE STRICT AS 'column_encrypt', 'col_enc_send';

CREATE TYPE encrypted_text (
    INTERNALLENGTH = variable,
    INPUT = col_enc_text_in,
    OUTPUT = col_enc_text_out,
    RECEIVE = col_enc_recv_text,
    SEND = col_enc_send_text,
    CATEGORY = 'S',
    ALIGNMENT = int4,
    STORAGE = extended
);

COMMENT ON TYPE encrypted_text IS
    'Encrypted text type. Requires encrypt.load_key() before accessing data.';

COMMENT ON TYPE encrypted_bytea IS
    'Encrypted bytea type. Requires encrypt.load_key() before accessing data.';

/*
 * =============================================================================
 * OPERATORS
 * =============================================================================
 */

-- Equality comparison (on decrypted plaintext)
CREATE FUNCTION col_enc_comp_eq_bytea(encrypted_bytea, encrypted_bytea) RETURNS boolean
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'col_enc_comp_eq_bytea';

CREATE FUNCTION col_enc_comp_eq_text(encrypted_text, encrypted_text) RETURNS boolean
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'col_enc_comp_eq_text';

CREATE OPERATOR = (
    PROCEDURE = col_enc_comp_eq_text,
    LEFTARG = encrypted_text,
    RIGHTARG = encrypted_text,
    RESTRICT = eqsel,
    JOIN = eqjoinsel
);

CREATE OPERATOR = (
    PROCEDURE = col_enc_comp_eq_bytea,
    LEFTARG = encrypted_bytea,
    RIGHTARG = encrypted_bytea,
    RESTRICT = eqsel,
    JOIN = eqjoinsel
);

-- Hash functions (on decrypted plaintext)
CREATE FUNCTION enc_hash_encbytea(encrypted_bytea) RETURNS integer
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'enc_hash_encrted_data';

CREATE FUNCTION enc_hash_enctext(encrypted_text) RETURNS integer
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'enc_hash_encrted_data';

-- Hash operator classes
CREATE OPERATOR FAMILY hash_bytea_enc_ops USING hash;
CREATE OPERATOR CLASS hash_bytea_enc_ops
    DEFAULT FOR TYPE encrypted_bytea USING hash FAMILY hash_bytea_enc_ops AS
    OPERATOR 1 =(encrypted_bytea, encrypted_bytea),
    FUNCTION 1 (encrypted_bytea, encrypted_bytea) enc_hash_encbytea(encrypted_bytea);

CREATE OPERATOR FAMILY hash_text_enc_ops USING hash;
CREATE OPERATOR CLASS hash_text_enc_ops
    DEFAULT FOR TYPE encrypted_text USING hash FAMILY hash_text_enc_ops AS
    OPERATOR 1 =(encrypted_text, encrypted_text),
    FUNCTION 1 (encrypted_text, encrypted_text) enc_hash_enctext(encrypted_text);

/*
 * =============================================================================
 * CASTS
 * =============================================================================
 */

-- Cast helper functions
CREATE FUNCTION enctext(boolean) RETURNS encrypted_text
    LANGUAGE c STRICT AS 'column_encrypt', 'bool_enc_text';

CREATE FUNCTION enctext(character) RETURNS encrypted_text
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'enc_text_trim';

CREATE FUNCTION enctext(inet) RETURNS encrypted_text
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'inet_enc_text';

CREATE FUNCTION enctext(xml) RETURNS encrypted_text
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'xml_enc_text';

CREATE FUNCTION regclass(encrypted_text) RETURNS regclass
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'enc_text_regclass';

-- Casts
CREATE CAST (encrypted_text AS text) WITH INOUT AS IMPLICIT;
CREATE CAST (text AS encrypted_text) WITH INOUT AS IMPLICIT;
CREATE CAST (boolean AS encrypted_text) WITH FUNCTION enctext(boolean) AS ASSIGNMENT;
CREATE CAST (character AS encrypted_text) WITH FUNCTION enctext(character) AS ASSIGNMENT;
CREATE CAST (cidr AS encrypted_text) WITH FUNCTION enctext(inet) AS ASSIGNMENT;
CREATE CAST (inet AS encrypted_text) WITH FUNCTION enctext(inet) AS ASSIGNMENT;
CREATE CAST (xml AS encrypted_text) WITH FUNCTION enctext(xml) AS ASSIGNMENT;
CREATE CAST (encrypted_text AS regclass) WITH FUNCTION regclass(encrypted_text) AS ASSIGNMENT;
CREATE CAST (encrypted_bytea AS bytea) WITH INOUT AS IMPLICIT;
CREATE CAST (bytea AS encrypted_bytea) WITH INOUT AS ASSIGNMENT;

/*
 * =============================================================================
 * INTERNAL FUNCTIONS (not exposed to users)
 * =============================================================================
 */

-- Key version extraction
CREATE FUNCTION enc_key_version(encrypted_text) RETURNS integer
    LANGUAGE c IMMUTABLE STRICT AS 'column_encrypt', 'enc_key_version_text';

CREATE FUNCTION enc_key_version(encrypted_bytea) RETURNS integer
    LANGUAGE c IMMUTABLE STRICT AS 'column_encrypt', 'enc_key_version_bytea';

-- Session keyring management (internal)
CREATE FUNCTION loaded_cipher_key_versions() RETURNS integer[]
    LANGUAGE c STABLE AS 'column_encrypt', 'enc_loaded_key_versions';

CREATE FUNCTION enc_store_key(text, text) RETURNS boolean
    LANGUAGE c STRICT AS 'column_encrypt', 'enc_store_key';

CREATE FUNCTION enc_rm_key() RETURNS boolean
    LANGUAGE c STRICT AS 'column_encrypt', 'enc_rm_key';

CREATE FUNCTION pgstat_actv_mask() RETURNS void
    LANGUAGE c STABLE STRICT AS 'column_encrypt', 'pgstat_actv_mask';

-- Revoke public access to internal functions
REVOKE EXECUTE ON FUNCTION enc_store_key(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_rm_key() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pgstat_actv_mask() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION loaded_cipher_key_versions() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_key_version(encrypted_text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_key_version(encrypted_bytea) FROM PUBLIC;

/*
 * =============================================================================
 * KEY STORAGE TABLE
 * =============================================================================
 */

CREATE TABLE cipher_key_table (
    key_version integer PRIMARY KEY CHECK (key_version > 0 AND key_version <= 32767),
    wrapped_key bytea NOT NULL,
    algorithm text NOT NULL DEFAULT 'aes',
    key_state text NOT NULL DEFAULT 'pending'
        CHECK (key_state IN ('pending', 'active', 'retired', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    state_changed_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz DEFAULT NULL,
    description text DEFAULT NULL,
    last_used_at timestamptz DEFAULT NULL,
    use_count bigint NOT NULL DEFAULT 0
);

-- Only one active key at a time
CREATE UNIQUE INDEX cipher_key_table_single_active_idx
    ON cipher_key_table ((1)) WHERE key_state = 'active';

-- Secure the table
REVOKE ALL ON TABLE cipher_key_table FROM PUBLIC;
ALTER TABLE cipher_key_table ENABLE ROW LEVEL SECURITY;
CREATE POLICY cipher_key_table_superuser_only ON cipher_key_table
    FOR ALL TO PUBLIC USING (false) WITH CHECK (false);

COMMENT ON TABLE cipher_key_table IS
    'Stores wrapped encryption keys. Access via encrypt.keys() function.';

/*
 * =============================================================================
 * ENCRYPT SCHEMA - PUBLIC API
 * =============================================================================
 */

CREATE SCHEMA encrypt;

COMMENT ON SCHEMA encrypt IS
    'Simplified column encryption API: register_key, load_key, rotate, verify';

/*
 * encrypt.register_key - Register a new encryption key
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
        -- Schema-qualify pgcrypto call to prevent search_path hijacking in SECURITY DEFINER context
        public.pgp_sym_encrypt(dek, passphrase, 'cipher-algo=aes256, s2k-mode=3'),
        'aes',
        CASE WHEN activate THEN 'active' ELSE 'pending' END,
        now()
    );

    RETURN v_key_id;
END;
$$;

COMMENT ON FUNCTION encrypt.register_key(TEXT, TEXT, BOOLEAN) IS
    'Registers a new encryption key. Returns the assigned key ID.';

/*
 * encrypt.load_key - Load key(s) into session memory
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
                -- Schema-qualify pgcrypto call to prevent search_path hijacking in SECURITY DEFINER context
                PERFORM enc_store_key(
                    public.pgp_sym_decrypt(wrapped_key, passphrase), algorithm
                ) FROM cipher_key_table WHERE key_version = v_key_version;
                v_count := v_count + 1;
            EXCEPTION WHEN OTHERS THEN
                PERFORM enc_rm_key();
                -- Restore previous GUC value (encrypt.key_version is INTEGER with min=1)
                IF v_prev_key_version IS NOT NULL AND v_prev_key_version <> '' THEN
                    PERFORM set_config('encrypt.key_version', v_prev_key_version, false);
                ELSE
                    -- Reset to default (1) since empty string is invalid for integer GUC
                    EXECUTE 'RESET encrypt.key_version';
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
            -- Schema-qualify pgcrypto call to prevent search_path hijacking in SECURITY DEFINER context
            PERFORM enc_store_key(
                public.pgp_sym_decrypt(wrapped_key, passphrase), algorithm
            ) FROM cipher_key_table WHERE key_state = 'active';

            UPDATE cipher_key_table
               SET last_used_at = now(), use_count = use_count + 1
             WHERE key_version = v_key_version;
            v_count := 1;
        EXCEPTION WHEN OTHERS THEN
            PERFORM enc_rm_key();
            -- Restore previous GUC value (encrypt.key_version is INTEGER with min=1)
            IF v_prev_key_version IS NOT NULL AND v_prev_key_version <> '' THEN
                PERFORM set_config('encrypt.key_version', v_prev_key_version, false);
            ELSE
                -- Reset to default (1) since empty string is invalid for integer GUC
                EXECUTE 'RESET encrypt.key_version';
            END IF;
            RAISE EXCEPTION 'incorrect passphrase'
                USING ERRCODE = 'invalid_password';
        END;
    END IF;

    RETURN v_count > 0;
END;
$$;

COMMENT ON FUNCTION encrypt.load_key(TEXT, BOOLEAN) IS
    'Loads encryption key(s) into session. Use all_versions=true for rotation.';

/*
 * encrypt.unload_key - Clear keys from session
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
    'Clears all encryption keys from session memory.';

/*
 * encrypt.activate_key - Make a key the active key
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

COMMENT ON FUNCTION encrypt.activate_key(INTEGER) IS
    'Makes the specified key version the active key for new encryptions.';

/*
 * encrypt.revoke_key - Revoke a key
 */
CREATE FUNCTION encrypt.revoke_key(key_id INTEGER) RETURNS BOOLEAN
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

COMMENT ON FUNCTION encrypt.revoke_key(INTEGER) IS
    'Revokes a key version, preventing it from being loaded.';

/*
 * encrypt.rotate - Re-encrypt column with active key
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

COMMENT ON FUNCTION encrypt.rotate(TEXT, TEXT, TEXT, INTEGER) IS
    'Re-encrypts column data with the current active key. Returns row count.';

/*
 * encrypt.verify - Verify encrypted data can be decrypted
 */
CREATE FUNCTION encrypt.verify(
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

COMMENT ON FUNCTION encrypt.verify(TEXT, TEXT, TEXT, INTEGER) IS
    'Verifies encrypted data can be decrypted with loaded keys.';

/*
 * encrypt.keys - List registered keys
 */
CREATE FUNCTION encrypt.keys() RETURNS TABLE(
    key_id INTEGER, key_state TEXT, algorithm TEXT,
    created_at TIMESTAMPTZ, last_used TIMESTAMPTZ, use_count BIGINT
)
    LANGUAGE sql SECURITY DEFINER SET search_path TO public
AS $$
    SELECT key_version, key_state, algorithm, created_at, last_used_at, use_count
      FROM cipher_key_table ORDER BY key_version;
$$;

COMMENT ON FUNCTION encrypt.keys() IS
    'Lists all registered encryption keys with state and usage.';

/*
 * encrypt.status - Quick status check
 */
CREATE FUNCTION encrypt.status() RETURNS TABLE(
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

COMMENT ON FUNCTION encrypt.status() IS
    'Returns current encryption status: key loaded, active key, column count.';

/*
 * encrypt.blind_index - Create searchable blind index
 */
CREATE FUNCTION encrypt.blind_index(value TEXT, hmac_key TEXT) RETURNS TEXT
    LANGUAGE sql IMMUTABLE STRICT
AS $$
    SELECT encode(hmac(convert_to(value, 'UTF8'), convert_to(hmac_key, 'UTF8'), 'sha256'), 'hex');
$$;

COMMENT ON FUNCTION encrypt.blind_index(TEXT, TEXT) IS
    'Creates HMAC-SHA256 blind index for searchable encryption.';

/*
 * =============================================================================
 * ROLE
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
    'Role for column_encrypt users. Grant to application roles.';

-- Grant schema and function access
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
GRANT EXECUTE ON FUNCTION loaded_cipher_key_versions() TO column_encrypt_user;

-- Revoke PUBLIC access to encrypt schema functions
REVOKE EXECUTE ON FUNCTION encrypt.register_key(TEXT, TEXT, BOOLEAN) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.load_key(TEXT, BOOLEAN) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.unload_key() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.activate_key(INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.revoke_key(INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.rotate(TEXT, TEXT, TEXT, INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.verify(TEXT, TEXT, TEXT, INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.keys() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.status() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.blind_index(TEXT, TEXT) FROM PUBLIC;
