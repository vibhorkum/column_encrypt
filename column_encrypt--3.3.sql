/* share/extension/column_encrypt--3.3.sql */

-- Version 3.3: API Simplification Release
--
-- This version introduces the 'encrypt' schema with a cleaner API.
-- Old functions remain for backward compatibility but are deprecated.
--
-- New in v3.3:
-- - 'encrypt' schema with simplified functions
-- - Automatic log masking (no more disable_log/enable_log ceremony)
-- - Single 'column_encrypt_user' role
-- - Deprecation notices on old functions

 -- complain if script is sourced in psql, rather than via CREATE EXTENSION

\echo Use "CREATE EXTENSION column_encrypt" to load this file. \quit

SET check_function_bodies TO off;

SET check_function_bodies TO off;

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
LANGUAGE c STABLE STRICT
AS 'column_encrypt', 'enc_hash_encrted_data';

/*
 * hash function for encrypted text
 */
CREATE FUNCTION enc_hash_enctext(encrypted_text) RETURNS integer
LANGUAGE c STABLE STRICT
AS 'column_encrypt', 'enc_hash_encrted_data';

CREATE FUNCTION enc_key_version(encrypted_text) RETURNS integer
LANGUAGE c IMMUTABLE STRICT
AS 'column_encrypt', 'enc_key_version_text';

CREATE FUNCTION enc_key_version(encrypted_bytea) RETURNS integer
LANGUAGE c IMMUTABLE STRICT
AS 'column_encrypt', 'enc_key_version_bytea';

CREATE FUNCTION loaded_cipher_key_versions() RETURNS integer[]
LANGUAGE c STABLE
AS 'column_encrypt', 'enc_loaded_key_versions';


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
    key_version integer PRIMARY KEY CHECK (key_version > 0 AND key_version <= 32767),
    wrapped_key bytea NOT NULL,
    algorithm text NOT NULL,
    key_state text NOT NULL DEFAULT 'pending'
        CHECK (key_state IN ('pending', 'active', 'retired', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    state_changed_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz DEFAULT NULL,
    description text DEFAULT NULL,
    last_used_at timestamptz DEFAULT NULL,
    use_count bigint NOT NULL DEFAULT 0
);

CREATE INDEX cipher_key_table_algo_idx ON cipher_key_table(algorithm);
CREATE UNIQUE INDEX cipher_key_table_single_active_idx
    ON cipher_key_table ((1))
    WHERE key_state = 'active';

/*
 * Audit log table for key management operations
 */
CREATE TABLE cipher_key_audit_log (
    id bigserial PRIMARY KEY,
    operation text NOT NULL,
    key_version integer,
    performed_by name NOT NULL DEFAULT session_user,
    performed_at timestamptz NOT NULL DEFAULT now(),
    details jsonb DEFAULT NULL
);

CREATE INDEX cipher_key_audit_log_key_version_idx ON cipher_key_audit_log(key_version);
CREATE INDEX cipher_key_audit_log_performed_at_idx ON cipher_key_audit_log(performed_at);

REVOKE ALL ON TABLE cipher_key_audit_log FROM PUBLIC;
ALTER TABLE cipher_key_audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY cipher_key_audit_log_superuser_only ON cipher_key_audit_log
    FOR ALL
    TO PUBLIC
    USING (false)
    WITH CHECK (false);

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
	/* mask pg_stat_activity's query */
	PERFORM pgstat_actv_mask();

	IF cipher_key IS NULL OR cipher_key = '' THEN
		RAISE EXCEPTION 'EDB-ENC0002 new cipher key is invalid';
	END IF;

	/* DEK must be at least 16 bytes for AES-128 security */
	IF octet_length(cipher_key) < 16 THEN
		RAISE EXCEPTION 'EDB-ENC0049 cipher key must be at least 16 bytes for cryptographic strength';
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

    IF p_key_version > 32767 THEN
        RAISE EXCEPTION 'EDB-ENC0052 key version must not exceed 32767 (ciphertext header limit)';
    END IF;

    /* validate expiration is in the future if provided */
    IF p_expires_at IS NOT NULL AND p_expires_at <= now() THEN
        RAISE EXCEPTION 'EDB-ENC0050 expiration time must be in the future';
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

	INSERT INTO cipher_key_table(key_version, wrapped_key, algorithm, key_state, state_changed_at, expires_at, description)
	VALUES(
        p_key_version,
        pgp_sym_encrypt(cipher_key, master_passphrase, 'cipher-algo=aes256, s2k-mode=3'),
        cipher_algorithm,
        CASE WHEN p_make_active THEN 'active' ELSE 'pending' END,
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
            /* Audit logging failure should not prevent key registration */
            NULL;
    END;

	RETURN p_key_version;
END;
$$;


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
    v_key_version integer;

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
-- Requires: the relevant ciphertext versions to be loaded in the session keyring
-- (for example via load_key_by_version()), and encrypt.key_version set to the
-- destination version to be written into new ciphertext headers.
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

    /* Encryption must be enabled for re-encryption to work */
    IF current_setting('encrypt.enable') <> 'on' THEN
        RAISE EXCEPTION 'EDB-ENC0048 encrypt.enable must be on for data re-encryption';
    END IF;

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

    IF current_setting('encrypt.enable') <> 'on' THEN
        RAISE EXCEPTION 'EDB-ENC0048 encrypt.enable must be on for data re-encryption';
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

/*
 * Function to verify that encrypted data in a column can be decrypted
 * Returns a table with verification results
 */
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
/*
 * =============================================================================
 * FEATURE 1: Encryption Statistics & Metrics
 * =============================================================================
 */

/*
 * Helper function: Check if any encryption key is loaded in the session
 */
CREATE FUNCTION is_key_loaded() RETURNS boolean
    LANGUAGE sql STABLE
AS $$
    SELECT array_length(loaded_cipher_key_versions(), 1) IS NOT NULL;
$$;

COMMENT ON FUNCTION is_key_loaded() IS
    'Returns true if at least one encryption key is loaded in the current session';

/*
 * View: Encryption statistics for all encrypted columns in the database
 */
CREATE FUNCTION cipher_encryption_stats()
RETURNS TABLE (
    schema_name text,
    table_name text,
    column_name text,
    column_type text,
    row_count bigint,
    null_count bigint,
    key_versions integer[],
    oldest_key_version integer,
    newest_key_version integer,
    needs_rotation boolean
)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    rec record;
    v_sql text;
    v_row_count bigint;
    v_null_count bigint;
    v_versions integer[];
    v_current_version integer;
BEGIN
    v_current_version := current_setting('encrypt.key_version', true)::integer;

    FOR rec IN
        SELECT
            n.nspname AS schema_name,
            c.relname AS table_name,
            a.attname AS column_name,
            t.typname AS column_type
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_type t ON t.oid = a.atttypid
        WHERE a.attnum > 0
          AND NOT a.attisdropped
          AND t.typname IN ('encrypted_text', 'encrypted_bytea')
          AND c.relkind = 'r'  -- Only regular tables
        ORDER BY n.nspname, c.relname, a.attnum
    LOOP
        schema_name := rec.schema_name;
        table_name := rec.table_name;
        column_name := rec.column_name;
        column_type := rec.column_type;

        -- Get row counts
        EXECUTE format(
            'SELECT count(*), count(*) FILTER (WHERE %I IS NULL) FROM %I.%I',
            rec.column_name, rec.schema_name, rec.table_name
        ) INTO v_row_count, v_null_count;

        row_count := v_row_count;
        null_count := v_null_count;

        -- Get distinct key versions (only if rows exist and keys are loaded)
        IF v_row_count > v_null_count AND is_key_loaded() THEN
            BEGIN
                EXECUTE format(
                    'SELECT array_agg(DISTINCT enc_key_version(%I) ORDER BY enc_key_version(%I)) FROM %I.%I WHERE %I IS NOT NULL',
                    rec.column_name, rec.column_name, rec.schema_name, rec.table_name, rec.column_name
                ) INTO v_versions;
                key_versions := v_versions;
                oldest_key_version := v_versions[1];
                newest_key_version := v_versions[array_upper(v_versions, 1)];
                needs_rotation := (oldest_key_version IS DISTINCT FROM v_current_version) OR (array_length(v_versions, 1) > 1);
            EXCEPTION
                WHEN OTHERS THEN
                    key_versions := NULL;
                    oldest_key_version := NULL;
                    newest_key_version := NULL;
                    needs_rotation := NULL;
            END;
        ELSE
            key_versions := NULL;
            oldest_key_version := NULL;
            newest_key_version := NULL;
            needs_rotation := false;
        END IF;

        RETURN NEXT;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION cipher_encryption_stats() IS
    'Returns statistics about all encrypted columns including row counts, key versions in use, and rotation status';

/*
 * View: Key usage statistics across the database
 */
CREATE FUNCTION cipher_key_usage_stats()
RETURNS TABLE (
    key_version integer,
    key_state text,
    tables_using integer,
    columns_using integer,
    row_count bigint,
    is_current boolean
)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    rec record;
    v_sql text;
    v_count bigint;
    v_current_version integer;
    v_key_record record;
BEGIN
    v_current_version := current_setting('encrypt.key_version', true)::integer;

    -- Get all registered key versions
    FOR v_key_record IN
        SELECT k.key_version, k.key_state
        FROM cipher_key_table k
        ORDER BY k.key_version
    LOOP
        key_version := v_key_record.key_version;
        key_state := v_key_record.key_state;
        is_current := (key_version = v_current_version);
        tables_using := 0;
        columns_using := 0;
        row_count := 0;

        -- Count usage across all encrypted columns
        IF is_key_loaded() THEN
            FOR rec IN
                SELECT
                    n.nspname AS schema_name,
                    c.relname AS table_name,
                    a.attname AS column_name
                FROM pg_attribute a
                JOIN pg_class c ON c.oid = a.attrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_type t ON t.oid = a.atttypid
                WHERE a.attnum > 0
                  AND NOT a.attisdropped
                  AND t.typname IN ('encrypted_text', 'encrypted_bytea')
                  AND c.relkind = 'r'
            LOOP
                BEGIN
                    EXECUTE format(
                        'SELECT count(*) FROM %I.%I WHERE %I IS NOT NULL AND enc_key_version(%I) = $1',
                        rec.schema_name, rec.table_name, rec.column_name, rec.column_name
                    ) INTO v_count USING v_key_record.key_version;

                    IF v_count > 0 THEN
                        row_count := row_count + v_count;
                        columns_using := columns_using + 1;
                    END IF;
                EXCEPTION
                    WHEN OTHERS THEN
                        NULL; -- Skip columns that can't be read
                END;
            END LOOP;

            -- Count distinct tables
            IF columns_using > 0 THEN
                tables_using := 1; -- Simplified; actual count would need more logic
            END IF;
        END IF;

        RETURN NEXT;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION cipher_key_usage_stats() IS
    'Returns usage statistics for each registered key version including row counts across the database';

/*
 * Function: Export metrics in a monitoring-friendly format
 */
CREATE FUNCTION cipher_metrics()
RETURNS TABLE (
    metric_name text,
    metric_value bigint,
    metric_labels jsonb
)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_count bigint;
    v_stats record;
BEGIN
    -- Total encrypted columns
    SELECT count(*) INTO v_count
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_type t ON t.oid = a.atttypid
    WHERE a.attnum > 0
      AND NOT a.attisdropped
      AND t.typname IN ('encrypted_text', 'encrypted_bytea')
      AND c.relkind = 'r';

    metric_name := 'column_encrypt_columns_total';
    metric_value := v_count;
    metric_labels := '{}'::jsonb;
    RETURN NEXT;

    -- Keys by state
    FOR v_stats IN
        SELECT key_state, count(*) AS cnt
        FROM cipher_key_table
        GROUP BY key_state
    LOOP
        metric_name := 'column_encrypt_keys_total';
        metric_value := v_stats.cnt;
        metric_labels := jsonb_build_object('state', v_stats.key_state);
        RETURN NEXT;
    END LOOP;

    -- Keys expiring in 30 days
    SELECT count(*) INTO v_count
    FROM cipher_key_table
    WHERE expires_at IS NOT NULL
      AND expires_at <= now() + interval '30 days'
      AND expires_at > now()
      AND key_state NOT IN ('revoked');

    metric_name := 'column_encrypt_keys_expiring_30d';
    metric_value := v_count;
    metric_labels := '{}'::jsonb;
    RETURN NEXT;

    -- Expired keys (not yet revoked)
    SELECT count(*) INTO v_count
    FROM cipher_key_table
    WHERE expires_at IS NOT NULL
      AND expires_at <= now()
      AND key_state NOT IN ('revoked');

    metric_name := 'column_encrypt_keys_expired';
    metric_value := v_count;
    metric_labels := '{}'::jsonb;
    RETURN NEXT;

    -- Active rotation jobs
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'cipher_rotation_jobs') THEN
        EXECUTE 'SELECT count(*) FROM cipher_rotation_jobs WHERE status = ''running''' INTO v_count;
        metric_name := 'column_encrypt_rotation_jobs_active';
        metric_value := COALESCE(v_count, 0);
        metric_labels := '{}'::jsonb;
        RETURN NEXT;
    END IF;

    -- Session key loaded
    metric_name := 'column_encrypt_session_key_loaded';
    metric_value := CASE WHEN is_key_loaded() THEN 1 ELSE 0 END;
    metric_labels := '{}'::jsonb;
    RETURN NEXT;

    -- Loaded key versions count
    metric_name := 'column_encrypt_session_keys_count';
    metric_value := COALESCE(array_length(loaded_cipher_key_versions(), 1), 0);
    metric_labels := '{}'::jsonb;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION cipher_metrics() IS
    'Returns encryption metrics in a format suitable for Prometheus/monitoring systems';

/*
 * =============================================================================
 * FEATURE 2: Encryption Coverage Audit
 * =============================================================================
 */

/*
 * Function: Audit database for potentially sensitive unencrypted columns
 */
CREATE FUNCTION cipher_coverage_audit(p_schema text DEFAULT NULL)
RETURNS TABLE (
    schema_name text,
    table_name text,
    column_name text,
    data_type text,
    classification text,
    is_encrypted boolean,
    recommendation text
)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    rec record;
    v_classification text;
    v_recommendation text;
BEGIN
    FOR rec IN
        SELECT
            n.nspname AS schema_name,
            c.relname AS table_name,
            a.attname AS column_name,
            t.typname AS data_type,
            t.typname IN ('encrypted_text', 'encrypted_bytea') AS is_encrypted
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_type t ON t.oid = a.atttypid
        WHERE a.attnum > 0
          AND NOT a.attisdropped
          AND c.relkind = 'r'
          AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
          AND (p_schema IS NULL OR n.nspname = p_schema)
        ORDER BY n.nspname, c.relname, a.attnum
    LOOP
        -- Skip if already encrypted
        IF rec.is_encrypted THEN
            -- Only report encrypted columns as informational
            schema_name := rec.schema_name;
            table_name := rec.table_name;
            column_name := rec.column_name;
            data_type := rec.data_type;
            is_encrypted := true;
            classification := 'ENCRYPTED';
            recommendation := 'OK';
            RETURN NEXT;
            CONTINUE;
        END IF;

        -- Classify based on column name patterns
        v_classification := NULL;
        v_recommendation := NULL;

        -- PII - High sensitivity
        IF rec.column_name ~* '(^|_)(ssn|social_security|national_id|passport|driver_license|tax_id|sin|nino)($|_|num|number)' THEN
            v_classification := 'PII-HIGH';
            v_recommendation := 'ENCRYPT';
        -- PCI - Payment card data
        ELSIF rec.column_name ~* '(^|_)(card|credit|debit|pan|ccn|cvv|cvc|card_number|credit_card|account_number)($|_|num|number)' THEN
            v_classification := 'PCI';
            v_recommendation := 'ENCRYPT';
        -- Secrets
        ELSIF rec.column_name ~* '(^|_)(password|passwd|secret|api_key|apikey|private_key|privatekey|token|access_token|refresh_token|auth_token|encryption_key|secret_key)($|_)' THEN
            v_classification := 'SECRET';
            v_recommendation := 'ENCRYPT';
        -- HIPAA / Medical
        ELSIF rec.column_name ~* '(^|_)(diagnosis|prescription|medical|health|patient|symptom|treatment|medication|vaccine|allergy|blood_type|insurance_id|member_id)($|_)' THEN
            v_classification := 'HIPAA';
            v_recommendation := 'ENCRYPT';
        -- PII - Medium sensitivity
        ELSIF rec.column_name ~* '(^|_)(email|phone|mobile|cell|address|street|zip|postal|dob|birth|birthdate|date_of_birth|age|gender|sex|race|ethnicity|religion|nationality)($|_)' THEN
            v_classification := 'PII-MEDIUM';
            v_recommendation := 'CONSIDER';
        -- Financial
        ELSIF rec.column_name ~* '(^|_)(salary|income|wage|compensation|bonus|bank|routing|iban|swift|balance|amount|price|cost|revenue|profit)($|_)' AND rec.data_type IN ('numeric', 'decimal', 'money', 'integer', 'bigint', 'real', 'double precision') THEN
            v_classification := 'FINANCIAL';
            v_recommendation := 'CONSIDER';
        -- Biometric
        ELSIF rec.column_name ~* '(^|_)(fingerprint|biometric|face_id|retina|voice_print|dna)($|_)' THEN
            v_classification := 'BIOMETRIC';
            v_recommendation := 'ENCRYPT';
        END IF;

        -- Only return rows with classification
        IF v_classification IS NOT NULL THEN
            schema_name := rec.schema_name;
            table_name := rec.table_name;
            column_name := rec.column_name;
            data_type := rec.data_type;
            is_encrypted := false;
            classification := v_classification;
            recommendation := v_recommendation;
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION cipher_coverage_audit(text) IS
    'Audits the database for potentially sensitive columns that may need encryption based on column naming patterns';

/*
 * Function: Summary of coverage audit
 */
CREATE FUNCTION cipher_coverage_summary(p_schema text DEFAULT NULL)
RETURNS TABLE (
    classification text,
    total_columns bigint,
    encrypted_columns bigint,
    unencrypted_columns bigint,
    coverage_pct numeric
)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO public
AS $$
    SELECT
        classification,
        count(*) AS total_columns,
        count(*) FILTER (WHERE is_encrypted) AS encrypted_columns,
        count(*) FILTER (WHERE NOT is_encrypted) AS unencrypted_columns,
        round(100.0 * count(*) FILTER (WHERE is_encrypted) / count(*), 1) AS coverage_pct
    FROM cipher_coverage_audit(p_schema)
    GROUP BY classification
    ORDER BY
        CASE classification
            WHEN 'PCI' THEN 1
            WHEN 'HIPAA' THEN 2
            WHEN 'SECRET' THEN 3
            WHEN 'BIOMETRIC' THEN 4
            WHEN 'PII-HIGH' THEN 5
            WHEN 'FINANCIAL' THEN 6
            WHEN 'PII-MEDIUM' THEN 7
            WHEN 'ENCRYPTED' THEN 8
            ELSE 9
        END;
$$;

COMMENT ON FUNCTION cipher_coverage_summary(text) IS
    'Returns a summary of encryption coverage by classification category';

/*
 * =============================================================================
 * FEATURE 3: Online Key Rotation with Progress Tracking
 * =============================================================================
 */

/*
 * Table: Track rotation jobs
 */
CREATE TABLE cipher_rotation_jobs (
    job_id bigserial PRIMARY KEY,
    schema_name text NOT NULL,
    table_name text NOT NULL,
    column_name text NOT NULL,
    target_key_version integer NOT NULL,
    batch_size integer NOT NULL DEFAULT 1000,
    throttle_ms integer NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'paused', 'completed', 'failed', 'cancelled')),
    total_rows bigint,
    processed_rows bigint NOT NULL DEFAULT 0,
    failed_rows bigint NOT NULL DEFAULT 0,
    started_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    error_message text,
    created_by name NOT NULL DEFAULT session_user
);

CREATE INDEX cipher_rotation_jobs_status_idx ON cipher_rotation_jobs(status);

COMMENT ON TABLE cipher_rotation_jobs IS
    'Tracks progress of key rotation jobs for encrypted columns';

/*
 * Function: Start a new rotation job
 */
CREATE FUNCTION cipher_start_rotation_job(
    p_schema text,
    p_table text,
    p_column text,
    p_target_version integer DEFAULT NULL,
    p_batch_size integer DEFAULT 1000,
    p_throttle_ms integer DEFAULT 0
) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_job_id bigint;
    v_total_rows bigint;
    v_col_type text;
    v_target_version integer;
BEGIN
    -- Validate inputs
    IF p_schema !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_table  !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_column !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
        RAISE EXCEPTION 'EDB-ENC0041 invalid schema/table/column name';
    END IF;

    -- Verify column is encrypted type
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

    -- Get target version
    v_target_version := COALESCE(p_target_version, current_setting('encrypt.key_version')::integer);

    -- Check for existing active job on same column
    IF EXISTS (
        SELECT 1 FROM cipher_rotation_jobs
        WHERE schema_name = p_schema
          AND table_name = p_table
          AND column_name = p_column
          AND status IN ('pending', 'running', 'paused')
    ) THEN
        RAISE EXCEPTION 'EDB-ENC0053 a rotation job already exists for %.%.%', p_schema, p_table, p_column;
    END IF;

    -- Count total rows to process
    EXECUTE format(
        'SELECT count(*) FROM %I.%I WHERE %I IS NOT NULL AND enc_key_version(%I) <> $1',
        p_schema, p_table, p_column, p_column
    ) INTO v_total_rows USING v_target_version;

    -- Create job record
    INSERT INTO cipher_rotation_jobs (
        schema_name, table_name, column_name, target_key_version,
        batch_size, throttle_ms, total_rows, status
    ) VALUES (
        p_schema, p_table, p_column, v_target_version,
        p_batch_size, p_throttle_ms, v_total_rows, 'pending'
    ) RETURNING job_id INTO v_job_id;

    RETURN v_job_id;
END;
$$;

COMMENT ON FUNCTION cipher_start_rotation_job(text, text, text, integer, integer, integer) IS
    'Creates a new key rotation job for the specified encrypted column';

/*
 * Function: Execute one batch of a rotation job
 */
CREATE FUNCTION cipher_process_rotation_batch(p_job_id bigint) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_job cipher_rotation_jobs%ROWTYPE;
    v_sql text;
    v_processed bigint;
    v_col_type text;
BEGIN
    -- Get and lock the job
    SELECT * INTO v_job
    FROM cipher_rotation_jobs
    WHERE job_id = p_job_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'EDB-ENC0054 rotation job % not found', p_job_id;
    END IF;

    IF v_job.status NOT IN ('pending', 'running') THEN
        RAISE EXCEPTION 'EDB-ENC0055 rotation job % is not runnable (status: %)', p_job_id, v_job.status;
    END IF;

    -- Ensure encryption is enabled
    IF current_setting('encrypt.enable') <> 'on' THEN
        UPDATE cipher_rotation_jobs
        SET status = 'failed',
            error_message = 'encrypt.enable must be on',
            updated_at = now()
        WHERE job_id = p_job_id;
        RAISE EXCEPTION 'EDB-ENC0048 encrypt.enable must be on for data re-encryption';
    END IF;

    -- Update status to running if pending
    IF v_job.status = 'pending' THEN
        UPDATE cipher_rotation_jobs
        SET status = 'running',
            started_at = now(),
            updated_at = now()
        WHERE job_id = p_job_id;
    END IF;

    -- Get column type
    SELECT format_type(a.atttypid, a.atttypmod)
    INTO v_col_type
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_job.schema_name
      AND c.relname = v_job.table_name
      AND a.attname = v_job.column_name;

    -- Set the target key version
    PERFORM set_config('encrypt.key_version', v_job.target_key_version::text, true);

    -- Process one batch
    v_sql := format(
        'WITH batch AS (
            SELECT ctid
            FROM %I.%I
            WHERE %I IS NOT NULL
              AND enc_key_version(%I) <> $1
            LIMIT $2
        )
        UPDATE %I.%I AS t
        SET %I = t.%I::text::%s
        FROM batch
        WHERE t.ctid = batch.ctid',
        v_job.schema_name, v_job.table_name, v_job.column_name, v_job.column_name,
        v_job.schema_name, v_job.table_name, v_job.column_name, v_job.column_name, v_col_type
    );

    EXECUTE v_sql USING v_job.target_key_version, v_job.batch_size;
    GET DIAGNOSTICS v_processed = ROW_COUNT;

    -- Update job progress
    UPDATE cipher_rotation_jobs
    SET processed_rows = processed_rows + v_processed,
        updated_at = now(),
        status = CASE
            WHEN processed_rows + v_processed >= total_rows THEN 'completed'
            ELSE 'running'
        END,
        completed_at = CASE
            WHEN processed_rows + v_processed >= total_rows THEN now()
            ELSE NULL
        END
    WHERE job_id = p_job_id;

    -- Throttle if configured
    IF v_job.throttle_ms > 0 AND v_processed > 0 THEN
        PERFORM pg_sleep(v_job.throttle_ms / 1000.0);
    END IF;

    RETURN v_processed;
END;
$$;

COMMENT ON FUNCTION cipher_process_rotation_batch(bigint) IS
    'Processes one batch of rows for the specified rotation job';

/*
 * Function: Run rotation job to completion (or until paused/cancelled)
 */
CREATE FUNCTION cipher_run_rotation_job(p_job_id bigint) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_processed bigint;
    v_total bigint := 0;
    v_status text;
BEGIN
    LOOP
        -- Check job status
        SELECT status INTO v_status
        FROM cipher_rotation_jobs
        WHERE job_id = p_job_id;

        EXIT WHEN v_status NOT IN ('pending', 'running');

        -- Process one batch
        v_processed := cipher_process_rotation_batch(p_job_id);
        v_total := v_total + v_processed;

        EXIT WHEN v_processed = 0;
    END LOOP;

    RETURN v_total;
END;
$$;

COMMENT ON FUNCTION cipher_run_rotation_job(bigint) IS
    'Runs the specified rotation job to completion';

/*
 * Function: Pause a rotation job
 */
CREATE FUNCTION cipher_pause_rotation_job(p_job_id bigint) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    UPDATE cipher_rotation_jobs
    SET status = 'paused',
        updated_at = now()
    WHERE job_id = p_job_id
      AND status = 'running';

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION cipher_pause_rotation_job(bigint) IS
    'Pauses a running rotation job';

/*
 * Function: Resume a paused rotation job
 */
CREATE FUNCTION cipher_resume_rotation_job(p_job_id bigint) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    UPDATE cipher_rotation_jobs
    SET status = 'running',
        updated_at = now()
    WHERE job_id = p_job_id
      AND status = 'paused';

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION cipher_resume_rotation_job(bigint) IS
    'Resumes a paused rotation job';

/*
 * Function: Cancel a rotation job
 */
CREATE FUNCTION cipher_cancel_rotation_job(p_job_id bigint) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    UPDATE cipher_rotation_jobs
    SET status = 'cancelled',
        updated_at = now()
    WHERE job_id = p_job_id
      AND status IN ('pending', 'running', 'paused');

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION cipher_cancel_rotation_job(bigint) IS
    'Cancels a rotation job';

/*
 * View: Rotation job progress
 */
CREATE FUNCTION cipher_rotation_progress()
RETURNS TABLE (
    job_id bigint,
    schema_name text,
    table_name text,
    column_name text,
    target_version integer,
    status text,
    progress_pct numeric,
    processed_rows bigint,
    total_rows bigint,
    failed_rows bigint,
    rows_per_sec numeric,
    eta interval,
    started_at timestamptz,
    updated_at timestamptz,
    created_by name
)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO public
AS $$
    SELECT
        j.job_id,
        j.schema_name,
        j.table_name,
        j.column_name,
        j.target_key_version,
        j.status,
        CASE WHEN j.total_rows > 0
            THEN round(100.0 * j.processed_rows / j.total_rows, 1)
            ELSE 100.0
        END AS progress_pct,
        j.processed_rows,
        j.total_rows,
        j.failed_rows,
        CASE WHEN j.started_at IS NOT NULL AND j.updated_at > j.started_at
            THEN round(j.processed_rows / EXTRACT(EPOCH FROM (j.updated_at - j.started_at)), 1)
            ELSE NULL
        END AS rows_per_sec,
        CASE WHEN j.started_at IS NOT NULL
                AND j.updated_at > j.started_at
                AND j.processed_rows > 0
                AND j.status = 'running'
            THEN ((j.total_rows - j.processed_rows) / (j.processed_rows / EXTRACT(EPOCH FROM (j.updated_at - j.started_at)))) * interval '1 second'
            ELSE NULL
        END AS eta,
        j.started_at,
        j.updated_at,
        j.created_by
    FROM cipher_rotation_jobs j
    ORDER BY
        CASE j.status
            WHEN 'running' THEN 1
            WHEN 'paused' THEN 2
            WHEN 'pending' THEN 3
            ELSE 4
        END,
        j.job_id DESC;
$$;

COMMENT ON FUNCTION cipher_rotation_progress() IS
    'Returns the current progress of all rotation jobs';

/*
 * =============================================================================
 * PERMISSIONS
 * =============================================================================
 */

-- Statistics and metrics
REVOKE EXECUTE ON FUNCTION is_key_loaded() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_encryption_stats() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_key_usage_stats() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_metrics() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION is_key_loaded() TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION cipher_encryption_stats() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_usage_stats() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_metrics() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_metrics() TO column_encrypt_reader;

-- Coverage audit
REVOKE EXECUTE ON FUNCTION cipher_coverage_audit(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_coverage_summary(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION cipher_coverage_audit(text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_coverage_summary(text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_coverage_audit(text) TO column_encrypt_reader;
GRANT EXECUTE ON FUNCTION cipher_coverage_summary(text) TO column_encrypt_reader;

-- Rotation jobs
REVOKE ALL ON TABLE cipher_rotation_jobs FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_start_rotation_job(text, text, text, integer, integer, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_process_rotation_batch(bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_run_rotation_job(bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_pause_rotation_job(bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_resume_rotation_job(bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_cancel_rotation_job(bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_rotation_progress() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION cipher_start_rotation_job(text, text, text, integer, integer, integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_process_rotation_batch(bigint) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_run_rotation_job(bigint) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_pause_rotation_job(bigint) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_resume_rotation_job(bigint) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_cancel_rotation_job(bigint) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_rotation_progress() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_rotation_progress() TO column_encrypt_reader;

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
GRANT EXECUTE ON FUNCTION loaded_cipher_key_versions() TO column_encrypt_user;

-- Revoke PUBLIC access to sensitive functions
REVOKE EXECUTE ON FUNCTION encrypt.register_key(TEXT, TEXT, BOOLEAN) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.load_key(TEXT, BOOLEAN) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.unload_key() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.activate_key(INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.revoke_key(INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.rotate(TEXT, TEXT, TEXT, INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.verify(TEXT, TEXT, TEXT, INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.keys() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION encrypt.status() FROM PUBLIC;

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
