/* column_encrypt--1.0--2.0.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION column_encrypt UPDATE TO '2.0'" to load this file. \quit

--
-- Upgrade from 1.0 to 2.0
--
-- Changes in this upgrade:
--   1. Restrict cipher_key_table access (REVOKE + Row-Level Security)
--   2. Replace register_cipher_key(text,text) with register_cipher_key(text,text,text)
--      that accepts a separate master passphrase (KEK) instead of using the key as
--      its own passphrase.
--   3. Remove Blowfish (bf) algorithm support — only 'aes' is allowed.
--   4. Upgrade key wrapping from s2k-mode=1 to s2k-mode=3 (iterated salted).
--   5. Add cipher_key_reencrypt_data(text,text,text) function for key rotation.
--

-- 1. Restrict cipher_key_table permissions
REVOKE ALL ON TABLE cipher_key_table FROM PUBLIC;
ALTER TABLE cipher_key_table ENABLE ROW LEVEL SECURITY;

-- Only superusers (who bypass RLS) can query this table directly
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'cipher_key_table'
          AND policyname = 'cipher_key_table_superuser_only'
    ) THEN
        EXECUTE $pol$
            CREATE POLICY cipher_key_table_superuser_only ON cipher_key_table
                FOR ALL
                TO PUBLIC
                USING (pg_catalog.current_setting('is_superuser') = 'on')
        $pol$;
    END IF;
END;
$$;

-- 2. Drop old 2-argument register_cipher_key and replace with 3-argument version
DROP FUNCTION IF EXISTS public.register_cipher_key(text, text);

CREATE FUNCTION register_cipher_key(text, text, text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
    AS $_$

DECLARE
    cipher_key        ALIAS FOR $1;
    cipher_algorithm  ALIAS FOR $2;
    master_passphrase ALIAS FOR $3;

    f_key_num SMALLINT;

BEGIN
    /* mask pg_stat_activity's query */
    PERFORM pgstat_actv_mask();

    /* if cipher_key_disable_log is not yet executed, output an error */
    IF (SELECT setting FROM pg_settings WHERE name = 'encrypt.enable') != 'on' THEN
        RAISE EXCEPTION 'EDB-ENC0036 you must call cipher_key_disable_log function first.';
    END IF;

    IF cipher_key IS NULL OR cipher_key = '' THEN
        RAISE EXCEPTION 'EDB-ENC0002 new cipher key is invalid';
    END IF;

    IF master_passphrase IS NULL OR master_passphrase = '' THEN
        RAISE EXCEPTION 'EDB-ENC0037 master passphrase is invalid';
    END IF;

    /* validate encryption algorithm — only aes is supported */
    IF cipher_algorithm != 'aes' THEN
        RAISE EXCEPTION 'EDB-ENC0003 invalid cipher algorithm "%", only "aes" is supported', cipher_algorithm;
    END IF;

    SET LOCAL search_path TO public;
    SET LOCAL enable_seqscan TO off;

    /* obtain lock of encryption key table */
    LOCK TABLE cipher_key_table IN EXCLUSIVE MODE;

    /* getting the number of encryption key */
    SELECT count(*) INTO f_key_num FROM cipher_key_table;
    /* if encryption key already exists */
    IF f_key_num = 1 THEN
        RAISE EXCEPTION 'EDB-ENC0009 a cypher encryption keys are exists in cipher_key_table';
    END IF;

    /* encrypt data key with master passphrase (KEK) using iterated salted S2K */
    INSERT INTO cipher_key_table(key, algorithm)
    VALUES(pgp_sym_encrypt($1, $3, 'cipher-algo=aes256, s2k-mode=3'), $2);
    RETURN 1;
END;
$_$;

-- 5. Add cipher_key_reencrypt_data function
DROP FUNCTION IF EXISTS public.cipher_key_reencrypt_data(text, text, text);

CREATE FUNCTION cipher_key_reencrypt_data(text, text, text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
    AS $_$
DECLARE
    p_schema    ALIAS FOR $1;
    p_table     ALIAS FOR $2;
    p_column    ALIAS FOR $3;
    v_sql       TEXT;
    v_count     BIGINT;
    v_col_type  TEXT;
BEGIN
    /* Mask pg_stat_activity */
    PERFORM pgstat_actv_mask();

    /* Require encryption to be enabled */
    IF (SELECT setting FROM pg_settings WHERE name = 'encrypt.enable') != 'on' THEN
        RAISE EXCEPTION 'EDB-ENC0036 you must call cipher_key_disable_log first.';
    END IF;

    /* Validate the schema/table/column names to prevent SQL injection */
    IF p_schema !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_table  !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_column !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
        RAISE EXCEPTION 'EDB-ENC0041 invalid schema/table/column name';
    END IF;

    /* Determine the column data type */
    SELECT data_type INTO v_col_type
    FROM information_schema.columns
    WHERE table_schema = p_schema
      AND table_name   = p_table
      AND column_name  = p_column;

    IF v_col_type IS NULL THEN
        RAISE EXCEPTION 'EDB-ENC0042 column %.%.% not found',
            p_schema, p_table, p_column;
    END IF;

    /*
     * Build and execute UPDATE that reads each row (triggering decrypt with
     * previous_key_detail via col_enc_text_out/_bytea_out), then writes it
     * back (triggering encrypt with current_key_detail via
     * col_enc_text_in/_bytea_in).
     *
     * The cast to text and back forces a decrypt+re-encrypt cycle.
     */
    v_sql := format(
        'UPDATE %I.%I SET %I = %I::text::%s',
        p_schema, p_table, p_column, p_column, v_col_type
    );

    EXECUTE v_sql;
    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END;
$_$;
