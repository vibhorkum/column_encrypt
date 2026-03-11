/* share/extension/column_encryption--2.0.sql */

 -- complain if script is sourced in psql, rather than via CREATE EXTENSION

\echo Use "CREATE EXTENSION column_encryption VERSION '2.0'" to load this file. \quit

SET check_function_bodies TO off;

--
-- Ensure we are loading recent functions
--
DROP TABLE IF EXISTS public.cipher_key_table;
DROP OPERATOR CLASS IF EXISTS public.hash_text_enc_ops USING hash;
DROP OPERATOR FAMILY IF EXISTS public.hash_text_enc_ops USING hash;
DROP OPERATOR CLASS IF EXISTS public.hash_bytea_enc_ops USING hash;
DROP OPERATOR FAMILY IF EXISTS public.hash_bytea_enc_ops USING hash;
DROP OPERATOR IF EXISTS public.= (encrypted_bytea, encrypted_bytea);
DROP OPERATOR IF EXISTS public.= (encrypted_text, encrypted_text);
DROP FUNCTION IF EXISTS public.regclass(encrypted_text);
DROP FUNCTION IF EXISTS public.rm_key_details();
DROP FUNCTION IF EXISTS public.load_key(text);
DROP FUNCTION IF EXISTS public.pgstat_actv_mask();
DROP FUNCTION IF EXISTS public.enctext(xml);
DROP FUNCTION IF EXISTS public.enctext(inet);
DROP FUNCTION IF EXISTS public.enctext(character);
DROP FUNCTION IF EXISTS public.enctext(boolean);
DROP FUNCTION IF EXISTS public.enc_store_prv_key(text, text);
DROP FUNCTION IF EXISTS public.enc_store_key(text, text);
DROP FUNCTION IF EXISTS public.enc_hash_enctext(encrypted_text);
DROP FUNCTION IF EXISTS public.enc_hash_encbytea(encrypted_bytea);
DROP FUNCTION IF EXISTS public.enc_rm_prv_key();
DROP FUNCTION IF EXISTS public.enc_rm_key();
DROP FUNCTION IF EXISTS public.col_enc_comp_eq_text(encrypted_text, encrypted_text);
DROP FUNCTION IF EXISTS public.col_enc_comp_eq_bytea(encrypted_bytea, encrypted_bytea);
DROP FUNCTION IF EXISTS public.register_cipher_key(text, text);
DROP FUNCTION IF EXISTS public.register_cipher_key(text, text, text);
DROP FUNCTION IF EXISTS public.cipher_key_reencrypt_data(text, text, text);
DROP FUNCTION IF EXISTS public.cipher_key_enable_log();
DROP FUNCTION IF EXISTS public.cipher_key_disable_log();
DROP TYPE IF EXISTS public.encrypted_text CASCADE;
DROP FUNCTION IF EXISTS public.col_enc_send(encrypted_text);
DROP FUNCTION IF EXISTS public.col_enc_recv(internal);
DROP FUNCTION IF EXISTS public.col_enc_text_out(encrypted_text);
DROP FUNCTION IF EXISTS public.col_enc_text_in(cstring);
DROP TYPE IF EXISTS public.encrypted_bytea CASCADE;
DROP FUNCTION IF EXISTS public.col_enc_send(encrypted_bytea);
DROP FUNCTION IF EXISTS public.col_enc_recv(internal);
DROP FUNCTION IF EXISTS public.col_enc_bytea_out(encrypted_bytea);
DROP FUNCTION IF EXISTS public.col_enc_bytea_in(cstring);

/*
 * Create encrypted types
 */

CREATE TYPE encrypted_bytea;
CREATE TYPE encrypted_text;

/*
 * input function for encrypted bytea
 */

CREATE FUNCTION col_enc_bytea_in(cstring) RETURNS encrypted_bytea
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'col_enc_bytea_in';

/*
 * Output function for encrypted bytea
 */

CREATE FUNCTION col_enc_bytea_out(encrypted_bytea) RETURNS cstring
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'col_enc_bytea_out';

/*
 * Define recv function for encrypted bytea
 */

CREATE FUNCTION col_enc_recv_bytea(internal) RETURNS encrypted_bytea
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encryption', 'col_enc_recv';

/*
 * Define send function for encrypted bytea
 */

CREATE FUNCTION col_enc_send_bytea(encrypted_bytea) RETURNS bytea
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encryption', 'col_enc_send';

/*
 * Define encrypted_bytea data type
 */

CREATE TYPE encrypted_bytea (
    INTERNALLENGTH = variable,
    INPUT = col_enc_bytea_in,
    OUTPUT = col_enc_bytea_out,
    RECEIVE = col_enc_recv_bytea,
    SEND = col_enc_send_bytea,
    ALIGNMENT = int4,
    STORAGE = extended
);

/*
 * Input function for encrypted_text
 */

CREATE FUNCTION col_enc_text_in(cstring) RETURNS encrypted_text
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'col_enc_text_in';

/*
 * Output function for encrypted_text
 */

CREATE FUNCTION col_enc_text_out(encrypted_text) RETURNS cstring
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'col_enc_text_out';


/*
 * Define recv function for encrypted text
 */

CREATE FUNCTION col_enc_recv_text(internal) RETURNS encrypted_text
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encryption', 'col_enc_recv';

/*
 * Define send function for encrypted text
 */

CREATE FUNCTION col_enc_send_text(encrypted_text) RETURNS bytea
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encryption', 'col_enc_send';

/*
 * Define encrypted text data type
 */
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


/*
 * index operator for encrypted binary type
 */

CREATE FUNCTION col_enc_comp_eq_bytea(encrypted_bytea, encrypted_bytea) RETURNS boolean
LANGUAGE c STABLE STRICT
AS 'column_encryption', 'col_enc_comp_eq_bytea';


/*
 * index operator for encrypted text type
 */

CREATE FUNCTION col_enc_comp_eq_text(encrypted_text, encrypted_text) RETURNS boolean
LANGUAGE c STABLE STRICT
AS 'column_encryption', 'col_enc_comp_eq_text';


/*
 * define index operator for encrypted
 * text
 */

CREATE OPERATOR = (
PROCEDURE = col_enc_comp_eq_text,
LEFTARG = encrypted_text,
RIGHTARG = encrypted_text,
RESTRICT = eqsel,
JOIN = eqjoinsel
);


/*
 * define index operator for encrypted
 * bytea
 */

CREATE OPERATOR = (
PROCEDURE = col_enc_comp_eq_bytea,
LEFTARG = encrypted_bytea,
RIGHTARG = encrypted_bytea,
RESTRICT = eqsel,
JOIN = eqjoinsel
);

/*
 * Hash function for encrypted bytea
 */

CREATE FUNCTION enc_hash_encbytea(encrypted_bytea) RETURNS integer
LANGUAGE c IMMUTABLE STRICT
AS 'column_encryption', 'enc_hash_encrted_data';

/*
 * hash function for encrypted text
 */
CREATE FUNCTION enc_hash_enctext(encrypted_text) RETURNS integer
LANGUAGE c IMMUTABLE STRICT
AS 'column_encryption', 'enc_hash_encrted_data';


/*
 * define hash index for encrypted binary
 */

CREATE OPERATOR FAMILY hash_bytea_enc_ops USING hash;

CREATE OPERATOR CLASS hash_bytea_enc_ops
DEFAULT FOR TYPE encrypted_bytea USING hash FAMILY hash_bytea_enc_ops AS
OPERATOR 1 =(encrypted_bytea,encrypted_bytea) ,
FUNCTION 1 (encrypted_bytea, encrypted_bytea) enc_hash_encbytea(encrypted_bytea);

/*
 * define hash index for encrypted text
 */

CREATE OPERATOR FAMILY hash_text_enc_ops USING hash;

CREATE OPERATOR CLASS hash_text_enc_ops
DEFAULT FOR TYPE encrypted_text USING hash FAMILY hash_text_enc_ops AS
OPERATOR 1 =(encrypted_text,encrypted_text) ,
FUNCTION 1 (encrypted_text, encrypted_text) enc_hash_enctext(encrypted_text);

/*
 * Define cast functions for encrypted type column
 */

CREATE FUNCTION enctext(boolean) RETURNS encrypted_text
LANGUAGE c STRICT
AS 'column_encryption', 'bool_enc_text';

CREATE FUNCTION enctext(character) RETURNS encrypted_text
LANGUAGE c STABLE STRICT
AS 'column_encryption', 'enc_text_trim';


CREATE FUNCTION enctext(inet) RETURNS encrypted_text
LANGUAGE c STABLE STRICT
AS 'column_encryption', 'inet_enc_text';


CREATE FUNCTION enctext(xml) RETURNS encrypted_text
LANGUAGE c STABLE STRICT
AS 'column_encryption', 'xml_enc_text';

CREATE FUNCTION regclass(encrypted_text) RETURNS regclass
LANGUAGE c STABLE STRICT
AS 'column_encryption', 'enc_text_regclass';

/*
 * encrypted text -> text
 */

CREATE CAST (encrypted_text AS text)
WITH INOUT AS IMPLICIT;

/*
 * text -> encrypted text
 */

CREATE CAST (text AS encrypted_text)
WITH INOUT AS IMPLICIT;

/*
 * boolean -> encrypted text
 */

CREATE CAST (boolean AS encrypted_text)
WITH FUNCTION enctext(boolean)
AS ASSIGNMENT;

/*
 * character -> encrypted text
 */

CREATE CAST (character AS encrypted_text)
WITH FUNCTION enctext(character)
AS ASSIGNMENT;

/*
 * cidr -> encrypted text
 */

CREATE CAST (cidr AS encrypted_text)
WITH FUNCTION enctext(inet)
AS ASSIGNMENT;

/*
 * inet -> encrypted text
 */

CREATE CAST (inet AS encrypted_text)
WITH FUNCTION enctext(inet)
AS ASSIGNMENT;

/*
 * xml -> encrypted text
 */

CREATE CAST (xml AS encrypted_text)
WITH FUNCTION enctext(xml)
AS ASSIGNMENT;

/*
 * encrypted text -> regclass
 */

CREATE CAST (encrypted_text AS regclass)
WITH FUNCTION regclass(encrypted_text)
AS ASSIGNMENT;

/*
 * binary -> encrypted binary
 */

CREATE CAST (encrypted_bytea AS bytea)
WITH INOUT
AS IMPLICIT;

/*
 * encrypted binary -> binary
 */
CREATE CAST (bytea AS encrypted_bytea)
WITH INOUT
AS ASSIGNMENT;

/*
 * define table for managing encryption key
 */

CREATE TABLE cipher_key_table (
key bytea,
algorithm text
);

CREATE INDEX algo_idx ON cipher_key_table(algorithm);

/* Restrict access: only superusers (who bypass RLS) may query this table */
REVOKE ALL ON TABLE cipher_key_table FROM PUBLIC;
ALTER TABLE cipher_key_table ENABLE ROW LEVEL SECURITY;

CREATE POLICY cipher_key_table_superuser_only ON cipher_key_table
    FOR ALL
    TO PUBLIC
    USING (pg_catalog.current_setting('is_superuser') = 'on');



/*
 * Function descriptions:
 * 1. cipher_key_disable_log:
 *      Function for log redaction of INSERT/UPDATE/DELETE/function calls
 *      Arguments - No arguments
 *      Returns - boolean (true/false)
 *
 * 2. cipher_key_enable_log:
 *      Function for enabling the logging of statements in postgresql logs
 *      Arguments - No Argument
 *      Returns - boolean (true/false)
 *
 * 3. cipher_key_reencrypt_data:
 *      Function to change the key and re-encrypt the encrypted column data
 *      Arguments - re-encrypt specified data periodically using encryption
 *          key which is specified custom parameter
 *      @return true if re-encryption is successfully done

*/

--
-- Name: cipher_key_disable_log(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION cipher_key_disable_log() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
    AS $$
BEGIN

	SET track_activities = off;
	SET encrypt.enable = on;
	RETURN TRUE;

END;
$$;


--
-- Name: cipher_key_enable_log(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION cipher_key_enable_log() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
    AS $$
BEGIN

	SET track_activities = DEFAULT;
	SET encrypt.enable = off;
	RETURN TRUE;

END;
$$;



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

	f_key_num SMALLINT;			/* number of encryption key*/

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
		RAISE EXCEPTION 'EDB-ENC0002 master passphrase is invalid';
	END IF;

	/* validate encryption algorithm — only AES is supported */
	IF cipher_algorithm != 'aes' THEN
		RAISE EXCEPTION 'EDB-ENC0003 invalid cipher algorithm "%", only "aes" is supported', cipher_algorithm;
	END IF;

	SET LOCAL search_path TO public;
	SET LOCAL enable_seqscan TO off;

	/* obtain lock of enryption key table */
	LOCK TABLE cipher_key_table IN EXCLUSIVE MODE;

	/* getting the number of encryption key */
	SELECT count(*) INTO f_key_num FROM cipher_key_table;
	/* if encryption key is already exist */
	IF f_key_num = 1 THEN
			RAISE EXCEPTION 'EDB-ENC0009 a cipher encryption key already exists in cipher_key_table';
	END IF;

	/* encrypt data key using the master passphrase (KEK) and register it */
	INSERT INTO cipher_key_table(key, algorithm)
	VALUES(pgp_sym_encrypt($1, $3, 'cipher-algo=aes256, s2k-mode=3'), $2);
	RETURN 1;
END;
$_$;


--
-- Name: enc_rm_key(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_rm_key() RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encryption', 'enc_rm_key';

--
-- Name: enc_rm_prv_key(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_rm_prv_key() RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encryption', 'enc_rm_prv_key';



--
-- Name: enc_store_key(text, text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_store_key(text, text) RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encryption', 'enc_store_key';



--
-- Name: enc_store_prv_key(text, text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_store_prv_key(text, text) RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encryption', 'enc_store_prv_key';


--
-- Name: pgstat_actv_mask(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION pgstat_actv_mask() RETURNS void
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'pgstat_actv_mask';



--
-- Name: load_key(text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION load_key(text) RETURNS boolean
    LANGUAGE plpgsql
    SET search_path TO public
    AS $_$

DECLARE
	cipher_key ALIAS FOR $1;

	f_algorithm TEXT;		/* encryption algorithm of lastest key */
	f_key_num INTEGER;		/* number of encryption key */
	f_result BOOLEAN;

BEGIN
	/* mask pg_stat_activity's query */
	PERFORM pgstat_actv_mask();

	/* if cipher_key_disable_log is not yet executed, output an error */
	IF (SELECT setting FROM pg_settings WHERE name = 'encrypt.enable') != 'on' THEN
		RAISE EXCEPTION 'EDB-ENC0036 you must call cipher_key_disable_log function first.';
	END IF;

	/* drop encryption key information in memory */
	PERFORM enc_rm_key();
	/* drop old-encryption key information in memory */
	PERFORM enc_rm_prv_key();

	IF cipher_key IS NOT NULL THEN
		/* get number of registered encryption key */
		SELECT count(*) INTO f_key_num FROM cipher_key_table ;

		/* return false, if there is no or too many encryption key */
		IF f_key_num = 0 THEN
			RETURN FALSE;
		ELSIF f_key_num>1 THEN
			RAISE EXCEPTION 'EDB-ENC0009 too many encryption keys are exists in cipher_key_table';
		END IF;

		BEGIN
			/* load encryption key table to memory */
			PERFORM enc_store_key(pgp_sym_decrypt(key, cipher_key), algorithm)
			FROM cipher_key_table;
		EXCEPTION
			WHEN SQLSTATE '39000' THEN
				PERFORM enc_rm_key();
				RAISE EXCEPTION 'EDB-ENC0012 cipher key is not correct';
		END;
	END IF;
	RETURN TRUE;
END;
$_$;



--
-- Name: cipher_key_reencrypt_data(text, text, text); Type: FUNCTION; Schema: public;
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

    /* Look up the column data type */
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
     * previous_key_detail via col_enc_text_out/_bytea_out), then writes it back
     * (triggering encrypt with current_key_detail via col_enc_text_in/_bytea_in).
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


--
-- Name: rm_key_details(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION rm_key_details() RETURNS boolean
    LANGUAGE plpgsql
    SET search_path TO public
    AS $$

BEGIN
	/* drop encryption key table in memory */
	IF (SELECT enc_rm_key()) THEN
		RETURN TRUE;
	ELSE
		RETURN FALSE;
	END IF;
END;
$$;

