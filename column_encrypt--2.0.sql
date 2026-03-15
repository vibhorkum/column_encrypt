/* share/extension/column_encrypt--2.0.sql */

 -- complain if script is sourced in psql, rather than via CREATE EXTENSION

\echo Use "CREATE EXTENSION column_encrypt" to load this file. \quit

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
DROP FUNCTION IF EXISTS public.load_key_by_version(text, integer);
DROP FUNCTION IF EXISTS public.column_encrypt_blind_index_text(text, text);
DROP FUNCTION IF EXISTS public.column_encrypt_blind_index_bytea(bytea, text);
DROP FUNCTION IF EXISTS public.activate_cipher_key(integer);
DROP FUNCTION IF EXISTS public.revoke_cipher_key(integer);
DROP FUNCTION IF EXISTS public.cipher_key_versions();
DROP FUNCTION IF EXISTS public.cipher_key_logical_replication_check(text, text);
DROP FUNCTION IF EXISTS public.cipher_key_reencrypt_data_batch(text, text, text, integer);
DROP FUNCTION IF EXISTS public.pgstat_actv_mask();
DROP FUNCTION IF EXISTS public.enctext(xml);
DROP FUNCTION IF EXISTS public.enctext(inet);
DROP FUNCTION IF EXISTS public.enctext(character);
DROP FUNCTION IF EXISTS public.enctext(boolean);
DROP FUNCTION IF EXISTS public.enc_key_version(encrypted_text);
DROP FUNCTION IF EXISTS public.enc_key_version(encrypted_bytea);
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
DROP FUNCTION IF EXISTS public.register_cipher_key(text, text, text, integer, boolean);
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
    AS 'column_encrypt', 'col_enc_bytea_in';

/*
 * Output function for encrypted bytea
 */

CREATE FUNCTION col_enc_bytea_out(encrypted_bytea) RETURNS cstring
    LANGUAGE c STABLE STRICT
    AS 'column_encrypt', 'col_enc_bytea_out';

/*
 * Define recv function for encrypted bytea
 */

CREATE FUNCTION col_enc_recv_bytea(internal) RETURNS encrypted_bytea
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encrypt', 'col_enc_recv';

/*
 * Define send function for encrypted bytea
 */

CREATE FUNCTION col_enc_send_bytea(encrypted_bytea) RETURNS bytea
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encrypt', 'col_enc_send';

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
    AS 'column_encrypt', 'col_enc_text_in';

/*
 * Output function for encrypted_text
 */

CREATE FUNCTION col_enc_text_out(encrypted_text) RETURNS cstring
    LANGUAGE c STABLE STRICT
    AS 'column_encrypt', 'col_enc_text_out';


/*
 * Define recv function for encrypted text
 */

CREATE FUNCTION col_enc_recv_text(internal) RETURNS encrypted_text
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encrypt', 'col_enc_recv';

/*
 * Define send function for encrypted text
 */

CREATE FUNCTION col_enc_send_text(encrypted_text) RETURNS bytea
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encrypt', 'col_enc_send';

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
AS 'column_encrypt', 'col_enc_comp_eq_bytea';


/*
 * index operator for encrypted text type
 */

CREATE FUNCTION col_enc_comp_eq_text(encrypted_text, encrypted_text) RETURNS boolean
LANGUAGE c STABLE STRICT
AS 'column_encrypt', 'col_enc_comp_eq_text';


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
AS 'column_encrypt', 'enc_hash_encrted_data';

/*
 * hash function for encrypted text
 */
CREATE FUNCTION enc_hash_enctext(encrypted_text) RETURNS integer
LANGUAGE c IMMUTABLE STRICT
AS 'column_encrypt', 'enc_hash_encrted_data';

CREATE FUNCTION enc_key_version(encrypted_text) RETURNS integer
LANGUAGE c IMMUTABLE STRICT
AS 'column_encrypt', 'enc_key_version_text';

CREATE FUNCTION enc_key_version(encrypted_bytea) RETURNS integer
LANGUAGE c IMMUTABLE STRICT
AS 'column_encrypt', 'enc_key_version_bytea';


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
AS 'column_encrypt', 'bool_enc_text';

CREATE FUNCTION enctext(character) RETURNS encrypted_text
LANGUAGE c STABLE STRICT
AS 'column_encrypt', 'enc_text_trim';


CREATE FUNCTION enctext(inet) RETURNS encrypted_text
LANGUAGE c STABLE STRICT
AS 'column_encrypt', 'inet_enc_text';


CREATE FUNCTION enctext(xml) RETURNS encrypted_text
LANGUAGE c STABLE STRICT
AS 'column_encrypt', 'xml_enc_text';

CREATE FUNCTION regclass(encrypted_text) RETURNS regclass
LANGUAGE c STABLE STRICT
AS 'column_encrypt', 'enc_text_regclass';

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
    key_version integer PRIMARY KEY CHECK (key_version > 0),
    wrapped_key bytea NOT NULL,
    algorithm text NOT NULL,
    key_state text NOT NULL DEFAULT 'pending'
        CHECK (key_state IN ('pending', 'active', 'retired', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    state_changed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX cipher_key_table_algo_idx ON cipher_key_table(algorithm);
CREATE UNIQUE INDEX cipher_key_table_single_active_idx
    ON cipher_key_table ((1))
    WHERE key_state = 'active';

/* Restrict access to cipher_key_table: only superusers can read it */
REVOKE ALL ON TABLE cipher_key_table FROM PUBLIC;
ALTER TABLE cipher_key_table ENABLE ROW LEVEL SECURITY;

/* Only superusers (who bypass RLS) can query this table directly */
CREATE POLICY cipher_key_table_superuser_only ON cipher_key_table
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
	RETURN TRUE;

END;
$$;



--
-- Name: register_cipher_key(text, text, text, integer, boolean); Type: FUNCTION;
-- Args: cipher_key, cipher_algorithm, master_passphrase (Key Encryption Key), key_version, make_active
--

CREATE FUNCTION register_cipher_key(text, text, text, integer, boolean) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
    AS $_$

DECLARE
	cipher_key  ALIAS FOR $1;
	cipher_algorithm ALIAS FOR $2;
	master_passphrase ALIAS FOR $3;
    p_key_version ALIAS FOR $4;
    p_make_active ALIAS FOR $5;

BEGIN
	/* mask pg_stat_activity's query */
	PERFORM pgstat_actv_mask();

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

    IF p_key_version IS NULL OR p_key_version <= 0 THEN
        RAISE EXCEPTION 'EDB-ENC0043 key version must be a positive integer';
    END IF;

    LOCK TABLE cipher_key_table IN EXCLUSIVE MODE;

    IF EXISTS (
        SELECT 1
        FROM cipher_key_table
        WHERE key_version = p_key_version
    ) THEN
        RAISE EXCEPTION 'EDB-ENC0044 key version % is already registered', p_key_version;
    END IF;

    IF p_make_active THEN
        UPDATE cipher_key_table
           SET key_state = 'retired',
               state_changed_at = now()
         WHERE key_state = 'active';
    END IF;

	INSERT INTO cipher_key_table(key_version, wrapped_key, algorithm, key_state, state_changed_at)
	VALUES(
        p_key_version,
        pgp_sym_encrypt(cipher_key, master_passphrase, 'cipher-algo=aes256, s2k-mode=3'),
        cipher_algorithm,
        CASE WHEN p_make_active THEN 'active' ELSE 'pending' END,
        now()
    );
	RETURN p_key_version;
END;
$_$;

CREATE FUNCTION register_cipher_key(text, text, text) RETURNS integer
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


--
-- Name: enc_rm_key(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_rm_key() RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encrypt', 'enc_rm_key';

--
-- Name: enc_rm_prv_key(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_rm_prv_key() RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encrypt', 'enc_rm_prv_key';



--
-- Name: enc_store_key(text, text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_store_key(text, text) RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encrypt', 'enc_store_key';



--
-- Name: enc_store_prv_key(text, text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_store_prv_key(text, text) RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encrypt', 'enc_store_prv_key';


--
-- Name: pgstat_actv_mask(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION pgstat_actv_mask() RETURNS void
    LANGUAGE c STABLE STRICT
    AS 'column_encrypt', 'pgstat_actv_mask';



--
-- Name: load_key(text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION load_key(text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
    AS $_$

DECLARE
	cipher_key ALIAS FOR $1;
    f_key_num INTEGER;		/* number of active keys */
    old_key_version text;

BEGIN
	/* mask pg_stat_activity's query */
	PERFORM pgstat_actv_mask();
    old_key_version := current_setting('encrypt.key_version', true);

	/* drop all key information in memory */
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
				PERFORM set_config('encrypt.key_version', key_version::text, true)
            FROM cipher_key_table
            WHERE key_state = 'active';

				PERFORM enc_store_key(pgp_sym_decrypt(wrapped_key, cipher_key), algorithm)
				FROM cipher_key_table
            WHERE key_state = 'active';
			EXCEPTION
				WHEN OTHERS THEN
					PERFORM enc_rm_key();
                    IF old_key_version IS NOT NULL THEN
                        PERFORM set_config('encrypt.key_version', old_key_version, true);
                    END IF;
					RAISE EXCEPTION 'EDB-ENC0012 cipher key is not correct';
			END;
		END IF;
	RETURN TRUE;
END;
$_$;

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
        PERFORM set_config('encrypt.key_version', requested_version::text, true);
        PERFORM enc_store_key(pgp_sym_decrypt(wrapped_key, master_passphrase), algorithm)
          FROM cipher_key_table
         WHERE key_version = requested_version
           AND key_state <> 'revoked';
        IF NOT FOUND THEN
            IF old_key_version IS NOT NULL THEN
                PERFORM set_config('encrypt.key_version', old_key_version, true);
            END IF;
            RETURN FALSE;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            IF old_key_version IS NOT NULL THEN
                PERFORM set_config('encrypt.key_version', old_key_version, true);
            END IF;
            RAISE EXCEPTION 'EDB-ENC0012 cipher key is not correct';
    END;

    RETURN TRUE;
END;
$$;



--
-- Name: rm_key_details(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION rm_key_details() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
    AS $$

BEGIN
	RETURN enc_rm_key();
END;
$$;

CREATE FUNCTION activate_cipher_key(integer) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
    AS $$
DECLARE
    requested_version ALIAS FOR $1;
    old_key_version text;
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM cipher_key_table
         WHERE key_version = requested_version
           AND key_state <> 'revoked'
    ) THEN
        RETURN FALSE;
    END IF;

    old_key_version := current_setting('encrypt.key_version', true);

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

    RETURN TRUE;
END;
$$;

CREATE FUNCTION revoke_cipher_key(integer) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
    AS $$
DECLARE
    requested_version ALIAS FOR $1;
BEGIN
    UPDATE cipher_key_table
       SET key_state = 'revoked',
           state_changed_at = now()
     WHERE key_version = requested_version;

    RETURN FOUND;
END;
$$;

CREATE FUNCTION cipher_key_versions()
RETURNS TABLE (
    key_version integer,
    algorithm text,
    key_state text,
    created_at timestamptz,
    state_changed_at timestamptz
)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO public
AS $$
    SELECT c.key_version, c.algorithm, c.key_state, c.created_at, c.state_changed_at
      FROM cipher_key_table AS c
     ORDER BY c.key_version;
$$;

CREATE FUNCTION column_encrypt_blind_index_text(text, text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
AS $$
    SELECT encode(
        hmac(
            convert_to($1, 'UTF8'),
            convert_to($2, 'UTF8'),
            'sha256'
        ),
        'hex'
    );
$$;

CREATE FUNCTION column_encrypt_blind_index_bytea(bytea, text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
AS $$
    SELECT encode(
        hmac(
            $1,
            convert_to($2, 'UTF8'),
            'sha256'
        ),
        'hex'
    );
$$;


--
-- Name: cipher_key_reencrypt_data(text, text, text); Type: FUNCTION
-- Args: schema_name, table_name, column_name
-- Re-encrypts all values in the specified encrypted column using the current key.
-- Requires: enc_store_prv_key() loaded with old key, enc_store_key() loaded with new key.
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

    /* Validate the schema/table/column names to prevent SQL injection */
    IF p_schema !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_table  !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_column !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
        RAISE EXCEPTION 'EDB-ENC0041 invalid schema/table/column name';
    END IF;

    SELECT format_type(a.atttypid, a.atttypmod)
      INTO v_col_type
      FROM pg_attribute a
      JOIN pg_class c
        ON c.oid = a.attrelid
      JOIN pg_namespace n
        ON n.oid = c.relnamespace
     WHERE n.nspname = p_schema
       AND c.relname = p_table
       AND a.attname = p_column
       AND a.attnum > 0
       AND NOT a.attisdropped;

    IF v_col_type IS NULL THEN
        RAISE EXCEPTION 'EDB-ENC0042 column %.%.% not found',
            p_schema, p_table, p_column;
    END IF;

    IF v_col_type NOT IN ('encrypted_text', 'encrypted_bytea') THEN
        RAISE EXCEPTION 'EDB-ENC0046 %.%.% is not an encrypted column',
            p_schema, p_table, p_column;
    END IF;

    /*
     * Build and execute UPDATE that reads each row (triggering decrypt with
     * the ciphertext header version), then writes it
     * back (triggering encrypt with the currently selected key version via
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

CREATE FUNCTION cipher_key_reencrypt_data_batch(text, text, text, integer) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
    AS $_$
DECLARE
    p_schema    ALIAS FOR $1;
    p_table     ALIAS FOR $2;
    p_column    ALIAS FOR $3;
    p_batch_size ALIAS FOR $4;
    v_sql       TEXT;
    v_count     BIGINT;
    v_col_type  TEXT;
BEGIN
    IF p_batch_size IS NULL OR p_batch_size <= 0 THEN
        RAISE EXCEPTION 'EDB-ENC0047 batch size must be a positive integer';
    END IF;

    SELECT format_type(a.atttypid, a.atttypmod)
      INTO v_col_type
      FROM pg_attribute a
      JOIN pg_class c
        ON c.oid = a.attrelid
      JOIN pg_namespace n
        ON n.oid = c.relnamespace
     WHERE n.nspname = p_schema
       AND c.relname = p_table
       AND a.attname = p_column
       AND a.attnum > 0
       AND NOT a.attisdropped;

    IF v_col_type IS NULL THEN
        RAISE EXCEPTION 'EDB-ENC0042 column %.%.% not found',
            p_schema, p_table, p_column;
    END IF;

    IF v_col_type NOT IN ('encrypted_text', 'encrypted_bytea') THEN
        RAISE EXCEPTION 'EDB-ENC0046 %.%.% is not an encrypted column',
            p_schema, p_table, p_column;
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

    RETURN QUERY
    SELECT
        CASE WHEN replica_identity_uses_encrypted THEN 'warning' ELSE 'info' END,
        'replica_identity',
        CASE WHEN replica_identity_uses_encrypted THEN 'check' ELSE 'ok' END,
        CASE
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
REVOKE EXECUTE ON FUNCTION register_cipher_key(text, text, text, integer, boolean) FROM PUBLIC;
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
REVOKE EXECUTE ON FUNCTION column_encrypt_blind_index_text(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION column_encrypt_blind_index_bytea(bytea, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_key_version(encrypted_text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_key_version(encrypted_bytea) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_store_key(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_store_prv_key(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_rm_key() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_rm_prv_key() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pgstat_actv_mask() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION cipher_key_disable_log() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_enable_log() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION register_cipher_key(text, text, text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION register_cipher_key(text, text, text, integer, boolean) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION activate_cipher_key(integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION revoke_cipher_key(integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_reencrypt_data(text, text, text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_reencrypt_data(text, text, text, integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_reencrypt_data_batch(text, text, text, integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_logical_replication_check(text, text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_versions() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION load_key(text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION load_key_by_version(text, integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION rm_key_details() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION column_encrypt_blind_index_text(text, text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION column_encrypt_blind_index_bytea(bytea, text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION enc_key_version(encrypted_text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION enc_key_version(encrypted_bytea) TO column_encrypt_admin;

GRANT EXECUTE ON FUNCTION load_key(text) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION load_key_by_version(text, integer) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION rm_key_details() TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION cipher_key_versions() TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION column_encrypt_blind_index_text(text, text) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION column_encrypt_blind_index_bytea(bytea, text) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION enc_key_version(encrypted_text) TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION enc_key_version(encrypted_bytea) TO column_encrypt_runtime;

GRANT EXECUTE ON FUNCTION cipher_key_versions() TO column_encrypt_reader;
GRANT EXECUTE ON FUNCTION cipher_key_logical_replication_check(text, text) TO column_encrypt_reader;
