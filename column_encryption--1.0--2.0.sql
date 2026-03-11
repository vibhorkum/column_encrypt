/* column_encryption--1.0--2.0.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION column_encryption UPDATE TO '2.0'" to load this file. \quit

--
-- Version 2.0 upgrade migration
--
-- Changes:
--   1. Restrict cipher_key_table permissions (REVOKE + RLS)
--   2. Replace register_cipher_key(text,text) with register_cipher_key(text,text,text)
--      using a separate master passphrase (KEK) instead of the data key itself
--   3. Remove Blowfish algorithm support; only AES is permitted
--   4. Implement cipher_key_reencrypt_data(text, text, text) for key rotation
--   5. Improve s2k-mode from 1 (salted) to 3 (iterated+salted) for better KDF
--

/* Restrict access to cipher_key_table */
REVOKE ALL ON TABLE cipher_key_table FROM PUBLIC;
ALTER TABLE cipher_key_table ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'cipher_key_table'
          AND policyname = 'cipher_key_table_superuser_only'
    ) THEN
        CREATE POLICY cipher_key_table_superuser_only ON cipher_key_table
            FOR ALL
            TO PUBLIC
            USING (pg_catalog.current_setting('is_superuser') = 'on');
    END IF;
END;
$$;

/* Drop old 2-argument register_cipher_key */
DROP FUNCTION IF EXISTS public.register_cipher_key(text, text);

/* Drop old cipher_key_reencrypt_data if exists from a prior partial upgrade */
DROP FUNCTION IF EXISTS public.cipher_key_reencrypt_data(text, text, text);

--
-- Name: register_cipher_key(text, text, text); Type: FUNCTION;
-- Args: $1 = cipher_key (data encryption key), $2 = cipher_algorithm,
--       $3 = master_passphrase (key encryption key used to wrap the data key)
--

CREATE FUNCTION register_cipher_key(text, text, text) RETURNS integer
    LANGUAGE plpgsql
    AS $_$

DECLARE
	cipher_key         ALIAS FOR $1;
	cipher_algorithm   ALIAS FOR $2;
	master_passphrase  ALIAS FOR $3;

	f_key_num SMALLINT;

BEGIN
	PERFORM pgstat_actv_mask();

	IF (SELECT setting FROM pg_settings WHERE name = 'encrypt.enable') != 'on' THEN
		RAISE EXCEPTION 'EDB-ENC0036 you must call cipher_key_disable_log function first.';
	END IF;

	IF cipher_key IS NULL OR cipher_key = '' THEN
		RAISE EXCEPTION 'EDB-ENC0002 new cipher key is invalid';
	END IF;

	IF master_passphrase IS NULL OR master_passphrase = '' THEN
		RAISE EXCEPTION 'EDB-ENC0002 master passphrase is invalid';
	END IF;

	IF cipher_algorithm != 'aes' THEN
		RAISE EXCEPTION 'EDB-ENC0003 invalid cipher algorithm "%", only "aes" is supported', cipher_algorithm;
	END IF;

	SET LOCAL search_path TO public;
	SET LOCAL enable_seqscan TO off;

	LOCK TABLE cipher_key_table IN EXCLUSIVE MODE;

	SELECT count(*) INTO f_key_num FROM cipher_key_table;
	IF f_key_num = 1 THEN
		RAISE EXCEPTION 'EDB-ENC0009 a cipher encryption key already exists in cipher_key_table';
	END IF;

	INSERT INTO cipher_key_table(key, algorithm)
	VALUES(pgp_sym_encrypt($1, $3, 'cipher-algo=aes256, s2k-mode=3'), $2);
	RETURN 1;
END;
$_$;


--
-- Name: cipher_key_reencrypt_data(text, text, text); Type: FUNCTION;
-- Re-encrypts all values in an encrypted column using the current key.
-- Requires: previous key loaded via enc_store_prv_key(), new key via enc_store_key().
-- Returns: number of rows re-encrypted.
--

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
    PERFORM pgstat_actv_mask();

    IF (SELECT setting FROM pg_settings WHERE name = 'encrypt.enable') != 'on' THEN
        RAISE EXCEPTION 'EDB-ENC0036 you must call cipher_key_disable_log first.';
    END IF;

    IF p_schema !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_table  !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_column !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
        RAISE EXCEPTION 'EDB-ENC0041 invalid schema/table/column name';
    END IF;

    SELECT data_type INTO v_col_type
    FROM information_schema.columns
    WHERE table_schema = p_schema
      AND table_name   = p_table
      AND column_name  = p_column;

    IF v_col_type IS NULL THEN
        RAISE EXCEPTION 'EDB-ENC0042 column %.%.% not found',
            p_schema, p_table, p_column;
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
