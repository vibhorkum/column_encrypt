/* contrib/column_encryption/column_encryption--1.0.sql */

 -- complain if script is sourced in psql, rather than via CREATE EXTENSION

\echo Use "CREATE EXTENSION column_encryption" to load this file. \quit

DROP TABLE IF EXISTS public.cipher_key_table;
DROP OPERATOR CLASS IF EXISTS public.hash_text_enc_ops USING hash;
DROP OPERATOR FAMILY IF EXISTS public.hash_text_enc_ops USING hash;
DROP OPERATOR CLASS IF EXISTS public.hash_bytea_enc_ops USING hash;
DROP OPERATOR FAMILY IF EXISTS public.hash_bytea_enc_ops USING hash;
DROP OPERATOR IF EXISTS public.= (encrypted_bytea, encrypted_bytea);
DROP OPERATOR IF EXISTS public.= (encrypted_text, encrypted_text);
DROP FUNCTION IF EXISTS public.regclass(encrypted_text);
DROP FUNCTION IF EXISTS public.remove_key_details();
DROP FUNCTION IF EXISTS public.load_key_details(text);
DROP FUNCTION IF EXISTS public.pg_stat_actv_mask();
DROP FUNCTION IF EXISTS public.enctext(xml);
DROP FUNCTION IF EXISTS public.enctext(inet);
DROP FUNCTION IF EXISTS public.enctext(character);
DROP FUNCTION IF EXISTS public.enctext(boolean);
DROP FUNCTION IF EXISTS public.enc_store_previous_key_detail(text, text);
DROP FUNCTION IF EXISTS public.enc_store_key_detail(text, text);
DROP FUNCTION IF EXISTS public.enc_rename_backupfile(text, text);
DROP FUNCTION IF EXISTS public.enc_hash_enctext(encrypted_text);
DROP FUNCTION IF EXISTS public.enc_hash_encbytea(encrypted_bytea);
DROP FUNCTION IF EXISTS public.enc_drop_previous_key_detail();
DROP FUNCTION IF EXISTS public.enc_remove_key_detail();
DROP FUNCTION IF EXISTS public.column_enc_comp_eq_text(encrypted_text, encrypted_text);
DROP FUNCTION IF EXISTS public.column_enc_comp_eq_bytea(encrypted_bytea, encrypted_bytea);
DROP FUNCTION IF EXISTS public.cipher_key_regist(text, text, text);
DROP FUNCTION IF EXISTS public.cipher_key_reencrypt_data(text, text, text);
DROP FUNCTION IF EXISTS public.cipher_key_enable_log();
DROP FUNCTION IF EXISTS public.cipher_key_disable_log();
DROP FUNCTION IF EXISTS public.cipher_key_backup();
DROP TYPE IF EXISTS public.encrypted_text CASCADE;
DROP FUNCTION IF EXISTS public.column_enc_send(encrypted_text);
DROP FUNCTION IF EXISTS public.column_enc_recv(internal);
DROP FUNCTION IF EXISTS public.column_enc_text_out(encrypted_text);
DROP FUNCTION IF EXISTS public.column_enc_text_in(cstring);
DROP TYPE IF EXISTS public.encrypted_bytea CASCADE;
DROP FUNCTION IF EXISTS public.column_enc_send(encrypted_bytea);
DROP FUNCTION IF EXISTS public.column_enc_recv(internal);
DROP FUNCTION IF EXISTS public.column_enc_bytea_out(encrypted_bytea);
DROP FUNCTION IF EXISTS public.column_enc_bytea_in(cstring);
--
-- Name: public; Type: SCHEMA; Schema: -; Owner: enterprisedb
--

--
-- Name: encrypted_bytea; Type: SHELL TYPE; Schema: public; Owner: enterprisedb
--

CREATE TYPE encrypted_bytea;


--
-- Name: column_enc_bytea_in(cstring); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION column_enc_bytea_in(cstring) RETURNS encrypted_bytea
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'column_enc_bytea_in';



--
-- Name: column_enc_bytea_out(encrypted_bytea); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION column_enc_bytea_out(encrypted_bytea) RETURNS cstring
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'column_enc_bytea_out';



--
-- Name: column_enc_recv(internal); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION column_enc_recv_bytea(internal) RETURNS encrypted_bytea
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encryption', 'column_enc_recv';



--
-- Name: column_enc_send(encrypted_bytea); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION column_enc_send_bytea(encrypted_bytea) RETURNS bytea
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encryption', 'column_enc_send';



--
-- Name: encrypted_bytea; Type: TYPE; Schema: public; Owner: enterprisedb
--

CREATE TYPE encrypted_bytea (
    INTERNALLENGTH = variable,
    INPUT = column_enc_bytea_in,
    OUTPUT = column_enc_bytea_out,
    RECEIVE = column_enc_recv_bytea,
    SEND = column_enc_send_bytea,
    ALIGNMENT = int4,
    STORAGE = extended
);



--
-- Name: encrypted_text; Type: SHELL TYPE; Schema: public; Owner: enterprisedb
--

CREATE TYPE encrypted_text;


--
-- Name: column_enc_text_in(cstring); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION column_enc_text_in(cstring) RETURNS encrypted_text
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'column_enc_text_in';



--
-- Name: column_enc_text_out(encrypted_text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION column_enc_text_out(encrypted_text) RETURNS cstring
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'column_enc_text_out';



--
-- Name: column_enc_recv(internal); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION column_enc_recv_text(internal) RETURNS encrypted_text
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encryption', 'column_enc_recv';



--
-- Name: column_enc_send(encrypted_text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION column_enc_send_text(encrypted_text) RETURNS bytea
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encryption', 'column_enc_send';



--
-- Name: encrypted_text; Type: TYPE; Schema: public; Owner: enterprisedb
--

CREATE TYPE encrypted_text (
    INTERNALLENGTH = variable,
    INPUT = column_enc_text_in,
    OUTPUT = column_enc_text_out,
    RECEIVE = column_enc_recv_text,
    SEND = column_enc_send_text,
    CATEGORY = 'S',
    ALIGNMENT = int4,
    STORAGE = extended
);



--
-- Name: cipher_key_backup(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION cipher_key_backup() RETURNS boolean
    LANGUAGE plpgsql
    SET search_path TO public
    AS $$

DECLARE
	f_filepath TEXT;	/* path of backupfile */
	f_old_filepath TEXT;	/* old backupfile */
	f_query TEXT;		/* dynamic SQL */
	f_dbname TEXT;		/* current dbname */
	result BOOLEAN;

BEGIN
	/* get path of backup file from column_encrypt.backup_dir */
	SELECT setting INTO f_filepath FROM pg_settings WHERE name = 'column_encrypt.backup_dir';

	/* if column_encrypt.backup_dir is not set, get value of data_directory */
	IF(f_filepath = '')THEN
		SELECT setting INTO f_filepath FROM pg_settings WHERE name = 'data_directory';

		IF f_filepath IS NULL THEN
			RAISE EXCEPTION 'EDB-ENC0014 could not get data directory path';
		END IF;
	END IF;

	/* get name of current db */
	SELECT current_database() INTO f_dbname;

	/* set filename of backup */
	f_filepath := f_filepath || E'/enc_backup_' || f_dbname;
	f_old_filepath := f_filepath;

	/* rename if "ck_backup" is already exists */
	SELECT enc_rename_backupfile(f_filepath, f_old_filepath) INTO result;

	IF result = FALSE THEN
		RAISE EXCEPTION 'EDB-ENC0015 could not rename old backup file of cipher key';
	END IF;

	/* backup current encryption key table */
	f_query := 'COPY cipher_key_table TO ''' || f_filepath || ''' BINARY';
	EXECUTE f_query;

	RETURN result;
END;
$$;



--
-- Name: cipher_key_disable_log(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION cipher_key_disable_log() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
    AS $$

DECLARE
	save_result BOOLEAN;	/* result of backup current parameter */

BEGIN

	SET track_activities = off;
	SET column_encrypt.mask_key_log = on;
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

DECLARE
	save_result BOOLEAN;

BEGIN

	SET track_activities = DEFAULT;
	SET column_encrypt.mask_key_log = off;
	RETURN TRUE;

END;
$$;



--
-- Name: cipher_key_reencrypt_data(text, text, text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION cipher_key_reencrypt_data(text, text, text) RETURNS boolean
    LANGUAGE plpgsql
    AS $_$

DECLARE

	old_cipher_key ALIAS FOR $1;
	old_cipher_algorithm ALIAS FOR $2;
	new_cipher_key  ALIAS FOR $3;

	f_rec RECORD;	/* store target update column */
	f_rec2 RECORD;	/* store target update row */
	f_cu	REFCURSOR;	/* fetch target update column */
	f_cu2	REFCURSOR;	/* fetch target update row */

	f_counter	BIGINT;		/* number of processed target record*/
	f_result	BIGINT;

	f_query TEXT;					/* store dynamic SQL string */
	
	f_relid BIGINT;
	f_nspname TEXT;
	f_relname TEXT;
	f_islast BOOLEAN;

BEGIN
	/* init */
	f_counter := 0;
	f_relid := 0;
	f_nspname = '';
	f_relname = '';
	f_islast = FALSE;

	SET LOCAL search_path TO public;
	SET LOCAL encrypt.enable TO on;
	SET LOCAL encrypt.noversionerror TO on;
	
	/* set new key to memory */
	PERFORM load_key_details(new_cipher_key);
	/* set old key to memory */
	PERFORM enc_store_previous_key_detail(old_cipher_key, old_cipher_algorithm);

	/* store column of user defined table */
	OPEN
		f_cu
	FOR
		SELECT a.attrelid, n.nspname, c.relname, a.attname, t.typname
		FROM pg_attribute a, pg_class c, pg_type t, pg_namespace n
		WHERE a.attrelid = c.oid
		AND t.oid = a.atttypid
		AND c.relnamespace = n.oid
		AND c.relkind = 'r'
		AND t.typname IN ('encrypted_text', 'encrypted_bytea')
		AND n.nspname != 'information_schema'
		AND n.nspname NOT LIKE E'pg\\_%'
		ORDER BY nspname, relname, attname;
	

	/* re-encryption */
	FETCH f_cu INTO f_rec;
	IF NOT FOUND THEN
		f_islast := TRUE;
	END IF;

	/* update each encrypted column */
	LOOP
		IF f_islast THEN
			EXIT;
		END IF;

		f_relid := f_rec.attrelid;
		f_nspname := f_rec.nspname;
		f_relname := f_rec.relname;

		f_query := 'UPDATE ONLY ' || quote_ident(f_rec.nspname) || '.' || quote_ident(f_rec.relname) || ' SET ';

		LOOP
			IF f_rec.typname = 'encrypted_text' THEN
				f_query := f_query || quote_ident(f_rec.attname) || ' = ' || quote_ident(f_rec.attname) || '::text::encrypted_text ';
			ELSE
				f_query := f_query || quote_ident(f_rec.attname) || ' = ' || quote_ident(f_rec.attname) || '::bytea::encrypted_bytea ';
			END IF;

			FETCH f_cu INTO f_rec;
			IF NOT FOUND THEN
				f_islast := TRUE;
			END IF;

			IF f_islast OR f_relid != f_rec.attrelid THEN
				f_query := f_query || ';';
				EXIT;
			ELSE
				f_query := f_query || ', ';
			END IF;
		END LOOP;

		RAISE INFO 'EDB-ENC0001 re-encryption of table "%"."%" was started[01]', f_nspname, f_relname;

		EXECUTE f_query;

		RAISE INFO 'EDB-ENC0002 re-encryption of table "%"."%" was completed[01]', f_nspname, f_relname;
	END LOOP;

	CLOSE f_cu;
	
	/* delete old key from memory */
	PERFORM enc_drop_previous_key_detail();
	/* drop key from memory */
	PERFORM remove_key_details();

	RETURN TRUE;
END;
$_$;



--
-- Name: cipher_key_regist(text, text, text, text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION cipher_key_regist(text, text, text) RETURNS integer
    LANGUAGE plpgsql
    AS $_$

DECLARE
	current_cipher_key  ALIAS FOR $1;
	cipher_key  ALIAS FOR $2;
	cipher_algorithm ALIAS FOR $3;
    --    cipher_owner ALIAS FOR $4;

	current_cipher_algorithm TEXT;
	
	f_key_num SMALLINT;			/* number of encryption key*/

BEGIN
	/* mask pg_stat_activity's query */
	PERFORM pg_stat_actv_mask();

	/* if cipher_key_disable_log is not yet executed, output an error */
	IF (SELECT setting FROM pg_settings WHERE name = 'column_encrypt.mask_key_log') != 'on' THEN
		RAISE EXCEPTION 'EDB-ENC0036 you must call cipher_key_disable_log function first.';
	END IF;

	IF cipher_key IS NULL OR cipher_key = '' THEN
		RAISE EXCEPTION 'EDB-ENC0002 new cipher key is invalid';
	END IF;

	/* validate encryption algorithm */
	IF cipher_algorithm != 'aes' AND cipher_algorithm != 'bf' THEN
		RAISE EXCEPTION 'EDB-ENC0003 invalid cipher algorithm "%"', cipher_algorithm;
	END IF;

	SET LOCAL search_path TO public;
	SET LOCAL enable_seqscan TO off;

	/* obtain lock of enryption key table */
	LOCK TABLE cipher_key_table IN EXCLUSIVE MODE;

	/* getting the number of encryption key */
	SELECT count(*) INTO f_key_num FROM cipher_key_table;
	/* if encryption key is already exist */
	IF f_key_num = 1 THEN
		IF current_cipher_key IS NULL THEN
			RAISE EXCEPTION 'EDB-ENC0008 current cipher key is not correct';
		END IF;
		/* if current key is valid and save current encryption algorithm*/
		BEGIN
			SELECT algorithm INTO current_cipher_algorithm FROM cipher_key_table WHERE  
                                                           pgp_sym_decrypt(key, current_cipher_key)=current_cipher_key;
		EXCEPTION
			WHEN SQLSTATE '39000' THEN
				RAISE EXCEPTION 'EDB-ENC0008 current cipher key is not correct';
		END;
		/* delete current key */
		DELETE FROM cipher_key_table;

	/* too many key is exists */
	ELSEIF f_key_num > 1 THEN
			RAISE EXCEPTION 'EDB-ENC0009 too many encryption keys are exists in cipher_key_table';
	END IF;
	
	/* encrypt and register new key */
	INSERT INTO cipher_key_table(key, algorithm) VALUES(pgp_sym_encrypt(cipher_key, cipher_key, 'cipher-algo=aes256, s2k-mode=1'), cipher_algorithm);
	
	/* backup encryption key table */
	PERFORM cipher_key_backup();
	/* reencrypt all data */
	IF f_key_num = 1 THEN
		PERFORM cipher_key_reencrypt_data(current_cipher_key, current_cipher_algorithm, cipher_key);
	END IF;

	/* return 1 */
	RETURN 1;
END;
$_$;



--
-- Name: column_enc_comp_eq_bytea(encrypted_bytea, encrypted_bytea); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION column_enc_comp_eq_bytea(encrypted_bytea, encrypted_bytea) RETURNS boolean
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'column_enc_comp_eq_bytea';



--
-- Name: column_enc_comp_eq_text(encrypted_text, encrypted_text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION column_enc_comp_eq_text(encrypted_text, encrypted_text) RETURNS boolean
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'column_enc_comp_eq_text';



--
-- Name: enc_remove_key_detail(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_remove_key_detail() RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encryption', 'enc_remove_key_detail';

--
-- Name: enc_drop_previous_key_detail(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_drop_previous_key_detail() RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encryption', 'enc_drop_previous_key_detail';

--
-- Name: enc_hash_encbytea(encrypted_bytea); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_hash_encbytea(encrypted_bytea) RETURNS integer
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encryption', 'enc_hash_encrted_data';

--
-- Name: enc_hash_enctext(encrypted_text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_hash_enctext(encrypted_text) RETURNS integer
    LANGUAGE c IMMUTABLE STRICT
    AS 'column_encryption', 'enc_hash_encrted_data';



--
-- Name: enc_rename_backupfile(text, text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_rename_backupfile(text, text) RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encryption', 'enc_rename_backupfile';



--
-- Name: enc_store_key_detail(text, text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_store_key_detail(text, text) RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encryption', 'enc_store_key_detail';



--
-- Name: enc_store_previous_key_detail(text, text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enc_store_previous_key_detail(text, text) RETURNS boolean
    LANGUAGE c STRICT
    AS 'column_encryption', 'enc_store_previous_key_detail';



--
-- Name: enctext(boolean); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enctext(boolean) RETURNS encrypted_text
    LANGUAGE c STRICT
    AS 'column_encryption', 'bool_enc_text';



--
-- Name: enctext(character); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enctext(character) RETURNS encrypted_text
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'enc_text_trim';



--
-- Name: enctext(inet); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enctext(inet) RETURNS encrypted_text
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'inet_enc_text';



--
-- Name: enctext(xml); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION enctext(xml) RETURNS encrypted_text
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'xml_enc_text';



--
-- Name: pg_stat_actv_mask(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION pg_stat_actv_mask() RETURNS void
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'pg_stat_actv_mask';



--
-- Name: load_key_details(text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION load_key_details(text) RETURNS boolean
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
	PERFORM pg_stat_actv_mask();

	/* if cipher_key_disable_log is not yet executed, output an error */
	IF (SELECT setting FROM pg_settings WHERE name = 'column_encrypt.mask_key_log') != 'on' THEN
		RAISE EXCEPTION 'EDB-ENC0036 you must call cipher_key_disable_log function first.';
	END IF;

	/* drop encryption key information in memory */
	PERFORM enc_remove_key_detail();
	/* drop old-encryption key information in memory */
	PERFORM enc_drop_previous_key_detail();

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
			PERFORM enc_store_key_detail(pgp_sym_decrypt(key, cipher_key), algorithm)
			FROM (SELECT key, algorithm FROM cipher_key_table ) AS ckt;
		EXCEPTION
			WHEN SQLSTATE '39000' THEN
				PERFORM enc_remove_key_detail();
				RAISE EXCEPTION 'EDB-ENC0012 cipher key is not correct';
		END;
	END IF;
	RETURN TRUE;
END;
$_$;



--
-- Name: remove_key_details(); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION remove_key_details() RETURNS boolean
    LANGUAGE plpgsql
    SET search_path TO public
    AS $$

BEGIN
	/* drop encryption key table in memory */
	IF (SELECT enc_remove_key_detail()) THEN
		RETURN TRUE;
	ELSE
		RETURN FALSE;
	END IF;
END;
$$;



--
-- Name: regclass(encrypted_text); Type: FUNCTION; Schema: public; Owner: enterprisedb
--

CREATE FUNCTION regclass(encrypted_text) RETURNS regclass
    LANGUAGE c STABLE STRICT
    AS 'column_encryption', 'column_enc_text_regclass';



--
-- Name: =; Type: OPERATOR; Schema: public; Owner: enterprisedb
--

CREATE OPERATOR = (
    PROCEDURE = column_enc_comp_eq_text,
    LEFTARG = encrypted_text,
    RIGHTARG = encrypted_text,
    RESTRICT = eqsel,
    JOIN = eqjoinsel
);



--
-- Name: =; Type: OPERATOR; Schema: public; Owner: enterprisedb
--

CREATE OPERATOR = (
    PROCEDURE = column_enc_comp_eq_bytea,
    LEFTARG = encrypted_bytea,
    RIGHTARG = encrypted_bytea,
    RESTRICT = eqsel,
    JOIN = eqjoinsel
);



--
-- Name: hash_bytea_enc_ops; Type: OPERATOR FAMILY; Schema: public; Owner: enterprisedb
--

CREATE OPERATOR FAMILY hash_bytea_enc_ops USING hash;



--
-- Name: hash_bytea_enc_ops; Type: OPERATOR CLASS; Schema: public; Owner: enterprisedb
--

CREATE OPERATOR CLASS hash_bytea_enc_ops
    DEFAULT FOR TYPE encrypted_bytea USING hash FAMILY hash_bytea_enc_ops AS
    OPERATOR 1 =(encrypted_bytea,encrypted_bytea) ,
    FUNCTION 1 (encrypted_bytea, encrypted_bytea) enc_hash_encbytea(encrypted_bytea);



--
-- Name: hash_text_enc_ops; Type: OPERATOR FAMILY; Schema: public; Owner: enterprisedb
--

CREATE OPERATOR FAMILY hash_text_enc_ops USING hash;



--
-- Name: hash_text_enc_ops; Type: OPERATOR CLASS; Schema: public; Owner: enterprisedb
--

CREATE OPERATOR CLASS hash_text_enc_ops
    DEFAULT FOR TYPE encrypted_text USING hash FAMILY hash_text_enc_ops AS
    OPERATOR 1 =(encrypted_text,encrypted_text) ,
    FUNCTION 1 (encrypted_text, encrypted_text) enc_hash_enctext(encrypted_text);



SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: cipher_key_table; Type: TABLE; Schema: public; Owner: enterprisedb
--

CREATE TABLE cipher_key_table (
    key bytea,
    algorithm text
);

CREATE INDEX algo_idx ON cipher_key_table(algorithm);

--
-- Name: cipher_key_table; Type: ACL; Schema: public; Owner: enterprisedb
--
