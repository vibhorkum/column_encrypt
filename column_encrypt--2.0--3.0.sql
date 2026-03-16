/* column_encrypt--2.0--3.0.sql */

\echo Use "ALTER EXTENSION column_encrypt UPDATE TO '3.0'" to load this file. \quit

SET check_function_bodies TO off;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'cipher_key_table'
           AND column_name = 'key_version'
    ) THEN
        EXECUTE 'ALTER TABLE public.cipher_key_table ADD COLUMN key_version integer';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'cipher_key_table'
           AND column_name = 'key'
    ) AND NOT EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'cipher_key_table'
           AND column_name = 'wrapped_key'
    ) THEN
        EXECUTE 'ALTER TABLE public.cipher_key_table RENAME COLUMN key TO wrapped_key';
    ELSIF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'cipher_key_table'
           AND column_name = 'key'
    ) THEN
        EXECUTE 'ALTER TABLE public.cipher_key_table ADD COLUMN IF NOT EXISTS wrapped_key bytea';
        EXECUTE 'UPDATE public.cipher_key_table SET wrapped_key = COALESCE(wrapped_key, key)';
        EXECUTE 'ALTER TABLE public.cipher_key_table DROP COLUMN key';
    ELSIF NOT EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'cipher_key_table'
           AND column_name = 'wrapped_key'
    ) THEN
        EXECUTE 'ALTER TABLE public.cipher_key_table ADD COLUMN wrapped_key bytea';
    END IF;
END;
$$;

ALTER TABLE public.cipher_key_table
    ADD COLUMN IF NOT EXISTS key_state text,
    ADD COLUMN IF NOT EXISTS created_at timestamptz,
    ADD COLUMN IF NOT EXISTS state_changed_at timestamptz,
    ADD COLUMN IF NOT EXISTS expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS description text,
    ADD COLUMN IF NOT EXISTS last_used_at timestamptz,
    ADD COLUMN IF NOT EXISTS use_count bigint;

UPDATE public.cipher_key_table
   SET key_version = COALESCE(key_version, 1),
       key_state = COALESCE(key_state, 'active'),
       created_at = COALESCE(created_at, now()),
       state_changed_at = COALESCE(state_changed_at, created_at, now()),
       use_count = COALESCE(use_count, 0);

ALTER TABLE public.cipher_key_table
    ALTER COLUMN key_version SET DEFAULT 1,
    ALTER COLUMN key_version SET NOT NULL,
    ALTER COLUMN wrapped_key SET NOT NULL,
    ALTER COLUMN key_state SET DEFAULT 'pending',
    ALTER COLUMN key_state SET NOT NULL,
    ALTER COLUMN created_at SET DEFAULT now(),
    ALTER COLUMN created_at SET NOT NULL,
    ALTER COLUMN state_changed_at SET DEFAULT now(),
    ALTER COLUMN state_changed_at SET NOT NULL,
    ALTER COLUMN use_count SET DEFAULT 0,
    ALTER COLUMN use_count SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.cipher_key_table'::regclass
           AND contype = 'p'
    ) THEN
        EXECUTE 'ALTER TABLE public.cipher_key_table ADD CONSTRAINT cipher_key_table_pkey PRIMARY KEY (key_version)';
    END IF;
END;
$$;

ALTER TABLE public.cipher_key_table
    DROP CONSTRAINT IF EXISTS cipher_key_table_key_state_check;

ALTER TABLE public.cipher_key_table
    ADD CONSTRAINT cipher_key_table_key_state_check
    CHECK (key_state IN ('pending', 'active', 'retired', 'revoked'));

CREATE INDEX IF NOT EXISTS cipher_key_table_algo_idx
    ON public.cipher_key_table(algorithm);

DROP INDEX IF EXISTS public.cipher_key_table_single_active_idx;
CREATE UNIQUE INDEX cipher_key_table_single_active_idx
    ON public.cipher_key_table ((1))
    WHERE key_state = 'active';

REVOKE ALL ON TABLE public.cipher_key_table FROM PUBLIC;
ALTER TABLE public.cipher_key_table ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cipher_key_table_superuser_only ON public.cipher_key_table;
CREATE POLICY cipher_key_table_superuser_only ON public.cipher_key_table
    FOR ALL
    TO PUBLIC
    USING (false)
    WITH CHECK (false);

/* Create audit log table if not exists */
CREATE TABLE IF NOT EXISTS public.cipher_key_audit_log (
    id bigserial PRIMARY KEY,
    operation text NOT NULL,
    key_version integer,
    performed_by name NOT NULL DEFAULT current_user,
    performed_at timestamptz NOT NULL DEFAULT now(),
    details jsonb DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS cipher_key_audit_log_key_version_idx
    ON public.cipher_key_audit_log(key_version);
CREATE INDEX IF NOT EXISTS cipher_key_audit_log_performed_at_idx
    ON public.cipher_key_audit_log(performed_at);

REVOKE ALL ON TABLE public.cipher_key_audit_log FROM PUBLIC;
ALTER TABLE public.cipher_key_audit_log ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cipher_key_audit_log_superuser_only ON public.cipher_key_audit_log;
CREATE POLICY cipher_key_audit_log_superuser_only ON public.cipher_key_audit_log
    FOR ALL
    TO PUBLIC
    USING (false)
    WITH CHECK (false);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'column_encrypt_admin') THEN
        EXECUTE 'CREATE ROLE column_encrypt_admin NOLOGIN';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'column_encrypt_runtime') THEN
        EXECUTE 'CREATE ROLE column_encrypt_runtime NOLOGIN';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'column_encrypt_reader') THEN
        EXECUTE 'CREATE ROLE column_encrypt_reader NOLOGIN';
    END IF;
END;
$$;

DROP FUNCTION IF EXISTS public.enc_key_version(public.encrypted_text);
CREATE FUNCTION enc_key_version(encrypted_text) RETURNS integer
LANGUAGE c IMMUTABLE STRICT
AS 'column_encrypt', 'enc_key_version_text';

DROP FUNCTION IF EXISTS public.enc_key_version(public.encrypted_bytea);
CREATE FUNCTION enc_key_version(encrypted_bytea) RETURNS integer
LANGUAGE c IMMUTABLE STRICT
AS 'column_encrypt', 'enc_key_version_bytea';

DROP FUNCTION IF EXISTS public.loaded_cipher_key_versions();
CREATE FUNCTION loaded_cipher_key_versions() RETURNS integer[]
LANGUAGE c STABLE
AS 'column_encrypt', 'enc_loaded_key_versions';

ALTER FUNCTION public.enc_hash_encbytea(public.encrypted_bytea) STABLE;
ALTER FUNCTION public.enc_hash_enctext(public.encrypted_text) STABLE;

CREATE OR REPLACE FUNCTION cipher_key_disable_log() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    SET track_activities = off;
    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION cipher_key_enable_log() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    SET track_activities = DEFAULT;
    RETURN TRUE;
END;
$$;

DROP FUNCTION IF EXISTS public.register_cipher_key(text, text, text, integer, boolean, timestamptz, text);
DROP FUNCTION IF EXISTS public.register_cipher_key(text, text, text, integer, boolean);
CREATE FUNCTION register_cipher_key(
    cipher_key text,
    cipher_algorithm text,
    master_passphrase text,
    p_key_version integer,
    p_make_active boolean,
    p_expires_at timestamptz DEFAULT NULL,
    p_description text DEFAULT NULL
) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    PERFORM pgstat_actv_mask();

    IF cipher_key IS NULL OR cipher_key = '' THEN
        RAISE EXCEPTION 'EDB-ENC0002 new cipher key is invalid';
    END IF;

    /* DEK must be at least 16 bytes for AES-128 security */
    IF length(cipher_key) < 16 THEN
        RAISE EXCEPTION 'EDB-ENC0049 cipher key must be at least 16 bytes for cryptographic strength';
    END IF;

    IF master_passphrase IS NULL OR master_passphrase = '' THEN
        RAISE EXCEPTION 'EDB-ENC0037 master passphrase is invalid';
    END IF;

    IF cipher_algorithm != 'aes' THEN
        RAISE EXCEPTION 'EDB-ENC0003 invalid cipher algorithm "%", only "aes" is supported', cipher_algorithm;
    END IF;

    IF p_key_version IS NULL OR p_key_version <= 0 THEN
        RAISE EXCEPTION 'EDB-ENC0043 key version must be a positive integer';
    END IF;

    /* validate expiration is in the future if provided */
    IF p_expires_at IS NOT NULL AND p_expires_at <= now() THEN
        RAISE EXCEPTION 'EDB-ENC0050 expiration time must be in the future';
    END IF;

    LOCK TABLE cipher_key_table IN EXCLUSIVE MODE;

    IF EXISTS (
        SELECT 1 FROM cipher_key_table WHERE key_version = p_key_version
    ) THEN
        RAISE EXCEPTION 'EDB-ENC0044 key version % is already registered', p_key_version;
    END IF;

    IF p_make_active THEN
        UPDATE cipher_key_table
           SET key_state = 'retired',
               state_changed_at = now()
         WHERE key_state = 'active';
    END IF;

    INSERT INTO cipher_key_table(key_version, wrapped_key, algorithm, key_state, created_at, state_changed_at, expires_at, description)
    VALUES (
        p_key_version,
        pgp_sym_encrypt(cipher_key, master_passphrase, 'cipher-algo=aes256, s2k-mode=3'),
        cipher_algorithm,
        CASE WHEN p_make_active THEN 'active' ELSE 'pending' END,
        now(),
        now(),
        p_expires_at,
        p_description
    );

    /* Log the operation (non-fatal if logging fails) */
    BEGIN
        INSERT INTO cipher_key_audit_log(operation, key_version, details)
        VALUES(
            'register',
            p_key_version,
            jsonb_build_object(
                'make_active', p_make_active,
                'expires_at', p_expires_at,
                'description', p_description
            )
        );
    EXCEPTION
        WHEN OTHERS THEN
            NULL;
    END;

    RETURN p_key_version;
END;
$$;


CREATE OR REPLACE FUNCTION register_cipher_key(text, text, text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    RETURN register_cipher_key(
        $1,
        $2,
        $3,
        current_setting('encrypt.key_version')::integer,
        true
    );
END;
$$;

CREATE OR REPLACE FUNCTION load_key(text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $_$
DECLARE
    cipher_key ALIAS FOR $1;
    f_key_num integer;
    old_key_version text;
    v_key_version integer;
BEGIN
    PERFORM pgstat_actv_mask();
    old_key_version := current_setting('encrypt.key_version', true);
    PERFORM enc_rm_key();

    IF cipher_key IS NOT NULL THEN
        SELECT count(*) INTO f_key_num
          FROM cipher_key_table
         WHERE key_state = 'active';

        IF f_key_num = 0 THEN
            RETURN FALSE;
        ELSIF f_key_num > 1 THEN
            RAISE EXCEPTION 'EDB-ENC0045 more than one active key exists in cipher_key_table';
        END IF;

        BEGIN
            SELECT key_version INTO v_key_version
              FROM cipher_key_table
             WHERE key_state = 'active';

            PERFORM set_config('encrypt.key_version', v_key_version::text, false);

            PERFORM enc_store_key(pgp_sym_decrypt(wrapped_key, cipher_key), algorithm)
              FROM cipher_key_table
             WHERE key_state = 'active';

            /* Update usage statistics */
            UPDATE cipher_key_table
               SET last_used_at = now(),
                   use_count = use_count + 1
             WHERE key_version = v_key_version;
        EXCEPTION
            WHEN OTHERS THEN
                PERFORM enc_rm_key();
                IF old_key_version IS NOT NULL THEN
                    PERFORM set_config('encrypt.key_version', old_key_version, false);
                END IF;
                RAISE EXCEPTION 'EDB-ENC0012 cipher key is not correct';
        END;
    END IF;

    RETURN TRUE;
END;
$_$;

DROP FUNCTION IF EXISTS public.load_key_by_version(text, integer);
CREATE FUNCTION load_key_by_version(text, integer) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    master_passphrase ALIAS FOR $1;
    requested_version ALIAS FOR $2;
    old_key_version text;
BEGIN
    IF requested_version IS NULL OR requested_version <= 0 THEN
        RAISE EXCEPTION 'EDB-ENC0043 key version must be a positive integer';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM cipher_key_table
         WHERE key_version = requested_version
           AND key_state <> 'revoked'
    ) THEN
        RETURN FALSE;
    END IF;

    old_key_version := current_setting('encrypt.key_version', true);
    PERFORM pgstat_actv_mask();

    BEGIN
        PERFORM set_config('encrypt.key_version', requested_version::text, false);
        PERFORM enc_store_key(pgp_sym_decrypt(wrapped_key, master_passphrase), algorithm)
          FROM cipher_key_table
         WHERE key_version = requested_version
           AND key_state <> 'revoked';
        IF NOT FOUND THEN
            IF old_key_version IS NOT NULL THEN
                PERFORM set_config('encrypt.key_version', old_key_version, false);
            END IF;
            RETURN FALSE;
        END IF;

        /* Update usage statistics */
        UPDATE cipher_key_table
           SET last_used_at = now(),
               use_count = use_count + 1
         WHERE key_version = requested_version;

        IF old_key_version IS NOT NULL THEN
            PERFORM set_config('encrypt.key_version', old_key_version, false);
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            IF old_key_version IS NOT NULL THEN
                PERFORM set_config('encrypt.key_version', old_key_version, false);
            END IF;
            RAISE EXCEPTION 'EDB-ENC0012 cipher key is not correct';
    END;

    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION rm_key_details() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    RETURN enc_rm_key();
END;
$$;

DROP FUNCTION IF EXISTS public.activate_cipher_key(integer);
CREATE FUNCTION activate_cipher_key(integer) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    requested_version ALIAS FOR $1;
    old_key_version text;
    old_active_version integer;
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM cipher_key_table
         WHERE key_version = requested_version
           AND key_state <> 'revoked'
    ) THEN
        RETURN FALSE;
    END IF;

    /* Check if key is expired */
    IF EXISTS (
        SELECT 1
          FROM cipher_key_table
         WHERE key_version = requested_version
           AND expires_at IS NOT NULL
           AND expires_at <= now()
    ) THEN
        RAISE EXCEPTION 'EDB-ENC0051 cannot activate expired key version %', requested_version;
    END IF;

    old_key_version := current_setting('encrypt.key_version', true);

    /* Get current active version for audit log */
    SELECT key_version INTO old_active_version
      FROM cipher_key_table
     WHERE key_state = 'active';

    BEGIN
        UPDATE cipher_key_table
           SET key_state = CASE
                   WHEN key_version = requested_version THEN 'active'
                   WHEN key_state = 'active' THEN 'retired'
                   ELSE key_state
               END,
               state_changed_at = CASE
                   WHEN key_version = requested_version OR key_state = 'active' THEN now()
                   ELSE state_changed_at
               END
         WHERE key_state <> 'revoked';

        PERFORM set_config('encrypt.key_version', requested_version::text, false);
    EXCEPTION
        WHEN OTHERS THEN
            IF old_key_version IS NOT NULL THEN
                PERFORM set_config('encrypt.key_version', old_key_version, false);
            END IF;
            RAISE;
    END;

    /* Log the operation (non-fatal if logging fails) */
    BEGIN
        INSERT INTO cipher_key_audit_log(operation, key_version, details)
        VALUES(
            'activate',
            requested_version,
            jsonb_build_object('previous_active_version', old_active_version)
        );
    EXCEPTION
        WHEN OTHERS THEN
            NULL;
    END;

    RETURN TRUE;
END;
$$;

DROP FUNCTION IF EXISTS public.revoke_cipher_key(integer);
CREATE FUNCTION revoke_cipher_key(integer) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    requested_version ALIAS FOR $1;
    old_state text;
BEGIN
    /* Get current state for audit log */
    SELECT key_state INTO old_state
      FROM cipher_key_table
     WHERE key_version = requested_version;

    UPDATE cipher_key_table
       SET key_state = 'revoked',
           state_changed_at = now()
     WHERE key_version = requested_version;

    IF FOUND THEN
        /* Log the operation (non-fatal if logging fails) */
        BEGIN
            INSERT INTO cipher_key_audit_log(operation, key_version, details)
            VALUES(
                'revoke',
                requested_version,
                jsonb_build_object('previous_state', old_state)
            );
        EXCEPTION
            WHEN OTHERS THEN
                NULL;
        END;
    END IF;

    RETURN FOUND;
END;
$$;

DROP FUNCTION IF EXISTS public.cipher_key_versions();
CREATE FUNCTION cipher_key_versions()
RETURNS TABLE (
    key_version integer,
    algorithm text,
    key_state text,
    created_at timestamptz,
    state_changed_at timestamptz,
    expires_at timestamptz,
    is_expired boolean,
    description text,
    last_used_at timestamptz,
    use_count bigint
)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO public
AS $$
    SELECT c.key_version, c.algorithm, c.key_state, c.created_at, c.state_changed_at,
           c.expires_at,
           (c.expires_at IS NOT NULL AND c.expires_at <= now()) AS is_expired,
           c.description,
           c.last_used_at,
           c.use_count
      FROM cipher_key_table AS c
     ORDER BY c.key_version;
$$;

/*
 * Function to check for and report expired keys
 */
DROP FUNCTION IF EXISTS public.cipher_key_check_expired();
CREATE FUNCTION cipher_key_check_expired()
RETURNS TABLE (
    key_version integer,
    key_state text,
    expires_at timestamptz,
    expired_since interval
)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO public
AS $$
    SELECT c.key_version, c.key_state, c.expires_at,
           (now() - c.expires_at) AS expired_since
      FROM cipher_key_table AS c
     WHERE c.expires_at IS NOT NULL
       AND c.expires_at <= now()
       AND c.key_state NOT IN ('revoked')
     ORDER BY c.expires_at;
$$;

/*
 * Function to view audit log (for admins)
 */
DROP FUNCTION IF EXISTS public.cipher_key_audit_log_view(integer, integer);
CREATE FUNCTION cipher_key_audit_log_view(
    p_limit integer DEFAULT 100,
    p_key_version integer DEFAULT NULL
)
RETURNS TABLE (
    id bigint,
    operation text,
    key_version integer,
    performed_by name,
    performed_at timestamptz,
    details jsonb
)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO public
AS $$
    SELECT l.id, l.operation, l.key_version, l.performed_by, l.performed_at, l.details
      FROM cipher_key_audit_log AS l
     WHERE (p_key_version IS NULL OR l.key_version = p_key_version)
     ORDER BY l.performed_at DESC
     LIMIT p_limit;
$$;

DROP FUNCTION IF EXISTS public.column_encrypt_blind_index_text(text, text);
CREATE FUNCTION column_encrypt_blind_index_text(text, text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
AS $$
    SELECT encode(hmac(convert_to($1, 'UTF8'), convert_to($2, 'UTF8'), 'sha256'), 'hex');
$$;

DROP FUNCTION IF EXISTS public.column_encrypt_blind_index_bytea(bytea, text);
CREATE FUNCTION column_encrypt_blind_index_bytea(bytea, text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
AS $$
    SELECT encode(hmac($1, convert_to($2, 'UTF8'), 'sha256'), 'hex');
$$;

CREATE OR REPLACE FUNCTION cipher_key_reencrypt_data(text, text, text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $_$
DECLARE
    p_schema    ALIAS FOR $1;
    p_table     ALIAS FOR $2;
    p_column    ALIAS FOR $3;
    v_sql       text;
    v_count     bigint;
    v_col_type  text;
BEGIN
    PERFORM pgstat_actv_mask();

    /* Encryption must be enabled for re-encryption to work */
    IF current_setting('encrypt.enable') <> 'on' THEN
        RAISE EXCEPTION 'EDB-ENC0048 encrypt.enable must be on for data re-encryption';
    END IF;

    IF p_schema !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_table  !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_column !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
        RAISE EXCEPTION 'EDB-ENC0041 invalid schema/table/column name';
    END IF;

    SELECT format_type(a.atttypid, a.atttypmod)
      INTO v_col_type
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = p_schema
       AND c.relname = p_table
       AND a.attname = p_column
       AND a.attnum > 0
       AND NOT a.attisdropped;

    IF v_col_type IS NULL THEN
        RAISE EXCEPTION 'EDB-ENC0042 column %.%.% not found', p_schema, p_table, p_column;
    END IF;

    IF v_col_type NOT IN ('encrypted_text', 'encrypted_bytea') THEN
        RAISE EXCEPTION 'EDB-ENC0046 %.%.% is not an encrypted column', p_schema, p_table, p_column;
    END IF;

    v_sql := format(
        'UPDATE %I.%I SET %I = %I::text::%s',
        p_schema, p_table, p_column, p_column, v_col_type
    );

    EXECUTE v_sql;
    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END;
$_$;

DROP FUNCTION IF EXISTS public.cipher_key_reencrypt_data_batch(text, text, text, integer);
CREATE FUNCTION cipher_key_reencrypt_data_batch(text, text, text, integer) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $_$
DECLARE
    p_schema     ALIAS FOR $1;
    p_table      ALIAS FOR $2;
    p_column     ALIAS FOR $3;
    p_batch_size ALIAS FOR $4;
    v_sql        text;
    v_count      bigint;
    v_col_type   text;
BEGIN
    IF p_batch_size IS NULL OR p_batch_size <= 0 THEN
        RAISE EXCEPTION 'EDB-ENC0047 batch size must be a positive integer';
    END IF;

    IF current_setting('encrypt.enable') <> 'on' THEN
        RAISE EXCEPTION 'EDB-ENC0048 encrypt.enable must be on for data re-encryption';
    END IF;

    SELECT format_type(a.atttypid, a.atttypmod)
      INTO v_col_type
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = p_schema
       AND c.relname = p_table
       AND a.attname = p_column
       AND a.attnum > 0
       AND NOT a.attisdropped;

    IF v_col_type IS NULL THEN
        RAISE EXCEPTION 'EDB-ENC0042 column %.%.% not found', p_schema, p_table, p_column;
    END IF;

    IF v_col_type NOT IN ('encrypted_text', 'encrypted_bytea') THEN
        RAISE EXCEPTION 'EDB-ENC0046 %.%.% is not an encrypted column', p_schema, p_table, p_column;
    END IF;

    v_sql := format(
        'WITH batch AS (
            SELECT ctid
              FROM %I.%I
             WHERE enc_key_version(%I) <> current_setting(''encrypt.key_version'')::integer
             LIMIT %s
         )
         UPDATE %I.%I AS t
            SET %I = t.%I::text::%s
           FROM batch
          WHERE t.ctid = batch.ctid',
        p_schema, p_table, p_column, p_batch_size,
        p_schema, p_table, p_column, p_column, v_col_type
    );

    EXECUTE v_sql;
    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END;
$_$;

DROP FUNCTION IF EXISTS public.cipher_key_reencrypt_data(text, text, text, integer);
CREATE FUNCTION cipher_key_reencrypt_data(text, text, text, integer) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    total_rows bigint := 0;
    processed_rows bigint;
BEGIN
    LOOP
        processed_rows := cipher_key_reencrypt_data_batch($1, $2, $3, $4);
        EXIT WHEN processed_rows = 0;
        total_rows := total_rows + processed_rows;
    END LOOP;

    RETURN total_rows;
END;
$$;

/*
 * Function to verify that encrypted data in a column can be decrypted
 */
DROP FUNCTION IF EXISTS public.cipher_verify_column_encryption(text, text, text, integer);
CREATE FUNCTION cipher_verify_column_encryption(text, text, text, integer DEFAULT 1000)
RETURNS TABLE (
    check_name text,
    status text,
    total_rows bigint,
    sampled_rows bigint,
    decryptable_rows bigint,
    failed_rows bigint,
    distinct_key_versions integer[],
    details text
)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $_$
DECLARE
    p_schema     ALIAS FOR $1;
    p_table      ALIAS FOR $2;
    p_column     ALIAS FOR $3;
    p_sample_size ALIAS FOR $4;
    v_col_type   text;
    v_total      bigint;
    v_sampled    bigint;
    v_success    bigint;
    v_failed     bigint;
    v_versions   integer[];
    v_sql        text;
    v_loaded     integer[];
    rec          record;
BEGIN
    /* Validate the schema/table/column names */
    IF p_schema !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_table  !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_column !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
        check_name := 'input_validation';
        status := 'error';
        details := 'EDB-ENC0041 invalid schema/table/column name';
        RETURN NEXT;
        RETURN;
    END IF;

    /* Check column type */
    SELECT format_type(a.atttypid, a.atttypmod)
      INTO v_col_type
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = p_schema
       AND c.relname = p_table
       AND a.attname = p_column
       AND a.attnum > 0
       AND NOT a.attisdropped;

    IF v_col_type IS NULL THEN
        check_name := 'column_exists';
        status := 'error';
        details := format('column %I.%I.%I not found', p_schema, p_table, p_column);
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_col_type NOT IN ('encrypted_text', 'encrypted_bytea') THEN
        check_name := 'column_type';
        status := 'error';
        details := format('column %I.%I.%I is type %s, not encrypted', p_schema, p_table, p_column, v_col_type);
        RETURN NEXT;
        RETURN;
    END IF;

    /* Get total row count */
    EXECUTE format('SELECT count(*) FROM %I.%I WHERE %I IS NOT NULL', p_schema, p_table, p_column)
       INTO v_total;

    /* Get loaded key versions */
    v_loaded := loaded_cipher_key_versions();

    IF v_loaded IS NULL OR array_length(v_loaded, 1) IS NULL THEN
        check_name := 'keys_loaded';
        status := 'error';
        total_rows := v_total;
        details := 'no encryption keys are loaded in the session';
        RETURN NEXT;
        RETURN;
    END IF;

    /* Get distinct key versions used in the column */
    EXECUTE format(
        'SELECT array_agg(DISTINCT enc_key_version(%I)) FROM %I.%I WHERE %I IS NOT NULL',
        p_column, p_schema, p_table, p_column
    ) INTO v_versions;

    /* Sample and test decryption */
    v_success := 0;
    v_failed := 0;
    v_sampled := 0;

    /* Count successful decryptions by casting to text (which triggers decryption) */
    BEGIN
        EXECUTE format(
            'SELECT count(*) FROM (
                SELECT %I::text
                  FROM %I.%I
                 WHERE %I IS NOT NULL
                 LIMIT %s
             ) sub',
            p_column, p_schema, p_table, p_column, p_sample_size
        ) INTO v_success;
        v_sampled := v_success;
        v_failed := 0;
    EXCEPTION
        WHEN OTHERS THEN
            /* Bulk decryption failed; try row-by-row to get accurate counts */
            v_success := 0;
            v_failed := 0;
            FOR rec IN EXECUTE format(
                'SELECT ctid FROM %I.%I WHERE %I IS NOT NULL LIMIT %s',
                p_schema, p_table, p_column, p_sample_size
            ) LOOP
                v_sampled := v_sampled + 1;
                BEGIN
                    EXECUTE format(
                        'SELECT %I::text FROM %I.%I WHERE ctid = $1',
                        p_column, p_schema, p_table
                    ) USING rec.ctid;
                    v_success := v_success + 1;
                EXCEPTION
                    WHEN OTHERS THEN
                        v_failed := v_failed + 1;
                END;
            END LOOP;
    END;

    check_name := 'decryption_verification';
    total_rows := v_total;
    sampled_rows := v_sampled;
    decryptable_rows := v_success;
    failed_rows := v_failed;
    distinct_key_versions := v_versions;

    IF v_failed = 0 THEN
        status := 'ok';
        details := format('all %s sampled rows decrypted successfully', v_sampled);
    ELSE
        status := 'error';
        details := format('%s of %s sampled rows failed to decrypt; check if required key versions %s are loaded (currently loaded: %s)',
                          v_failed, v_sampled, v_versions, v_loaded);
    END IF;

    RETURN NEXT;
    RETURN;
END;
$_$;

DROP FUNCTION IF EXISTS public.cipher_key_logical_replication_check(text, text);
CREATE FUNCTION cipher_key_logical_replication_check(text, text)
RETURNS TABLE (
    severity text,
    check_name text,
    status text,
    details text
)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    p_schema ALIAS FOR $1;
    p_table ALIAS FOR $2;
    encrypted_column_count integer;
    replica_identity_uses_encrypted boolean;
    replica_identity_full boolean;
BEGIN
    RETURN QUERY
    SELECT
        CASE WHEN current_setting('wal_level') = 'logical' THEN 'info' ELSE 'warning' END,
        'wal_level',
        CASE WHEN current_setting('wal_level') = 'logical' THEN 'ok' ELSE 'check' END,
        format('wal_level is %s', current_setting('wal_level'));

    SELECT count(*)
      INTO encrypted_column_count
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_type t ON t.oid = a.atttypid
     WHERE n.nspname = p_schema
       AND c.relname = p_table
       AND a.attnum > 0
       AND NOT a.attisdropped
       AND t.typname IN ('encrypted_text', 'encrypted_bytea');

    RETURN QUERY
    SELECT
        CASE WHEN encrypted_column_count > 0 THEN 'info' ELSE 'warning' END,
        'encrypted_columns',
        CASE WHEN encrypted_column_count > 0 THEN 'ok' ELSE 'check' END,
        format('table %I.%I has %s encrypted columns', p_schema, p_table, encrypted_column_count);

    SELECT EXISTS (
        SELECT 1
          FROM pg_index i
          JOIN pg_class c ON c.oid = i.indrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON true
          JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
          JOIN pg_type t ON t.oid = a.atttypid
         WHERE n.nspname = p_schema
           AND c.relname = p_table
           AND i.indisreplident
           AND t.typname IN ('encrypted_text', 'encrypted_bytea')
    ) INTO replica_identity_uses_encrypted;

    SELECT c.relreplident = 'f'
      INTO replica_identity_full
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = p_schema
       AND c.relname = p_table;

    RETURN QUERY
    SELECT
        CASE
            WHEN replica_identity_full AND encrypted_column_count > 0 THEN 'warning'
            WHEN replica_identity_uses_encrypted THEN 'warning'
            ELSE 'info'
        END,
        'replica_identity',
        CASE
            WHEN replica_identity_full AND encrypted_column_count > 0 THEN 'check'
            WHEN replica_identity_uses_encrypted THEN 'check'
            ELSE 'ok'
        END,
        CASE
            WHEN replica_identity_full AND encrypted_column_count > 0 THEN 'replica identity is FULL and encrypted columns will participate in subscriber row matching; confirm ciphertext replication semantics and key availability'
            WHEN replica_identity_uses_encrypted THEN 'replica identity includes encrypted columns; confirm subscriber semantics and key availability'
            ELSE 'replica identity does not include encrypted columns'
        END;

    RETURN QUERY
    SELECT
        'warning',
        'subscriber_prereqs',
        'manual',
        'logical subscribers must have the column_encrypt extension installed and must load the correct keys independently; keys are not replicated';
END;
$$;

REVOKE EXECUTE ON FUNCTION cipher_key_disable_log() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_key_enable_log() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION register_cipher_key(text, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION register_cipher_key(text, text, text, integer, boolean, timestamptz, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_key_check_expired() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_key_audit_log_view(integer, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION load_key(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION load_key_by_version(text, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION rm_key_details() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION activate_cipher_key(integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION revoke_cipher_key(integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_key_versions() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_key_reencrypt_data(text, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_key_reencrypt_data(text, text, text, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_key_reencrypt_data_batch(text, text, text, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_key_logical_replication_check(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_verify_column_encryption(text, text, text, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION column_encrypt_blind_index_text(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION column_encrypt_blind_index_bytea(bytea, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_key_version(encrypted_text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_key_version(encrypted_bytea) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION loaded_cipher_key_versions() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_store_key(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_store_prv_key(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_rm_key() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_rm_prv_key() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pgstat_actv_mask() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION cipher_key_disable_log() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_enable_log() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION register_cipher_key(text, text, text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION register_cipher_key(text, text, text, integer, boolean, timestamptz, text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_check_expired() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_audit_log_view(integer, integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION activate_cipher_key(integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION revoke_cipher_key(integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_reencrypt_data(text, text, text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_reencrypt_data(text, text, text, integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_reencrypt_data_batch(text, text, text, integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_logical_replication_check(text, text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_verify_column_encryption(text, text, text, integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_versions() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION load_key(text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION load_key_by_version(text, integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION rm_key_details() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION column_encrypt_blind_index_text(text, text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION column_encrypt_blind_index_bytea(bytea, text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION enc_key_version(encrypted_text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION enc_key_version(encrypted_bytea) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION loaded_cipher_key_versions() TO column_encrypt_admin;

GRANT EXECUTE ON FUNCTION load_key(text) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION load_key_by_version(text, integer) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION rm_key_details() TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION cipher_key_versions() TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION column_encrypt_blind_index_text(text, text) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION column_encrypt_blind_index_bytea(bytea, text) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION enc_key_version(encrypted_text) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION enc_key_version(encrypted_bytea) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION loaded_cipher_key_versions() TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION cipher_verify_column_encryption(text, text, text, integer) TO column_encrypt_runtime;

GRANT EXECUTE ON FUNCTION cipher_key_versions() TO column_encrypt_reader;
GRANT EXECUTE ON FUNCTION cipher_key_logical_replication_check(text, text) TO column_encrypt_reader;
GRANT EXECUTE ON FUNCTION cipher_key_check_expired() TO column_encrypt_reader;
GRANT EXECUTE ON FUNCTION cipher_key_audit_log_view(integer, integer) TO column_encrypt_reader;
