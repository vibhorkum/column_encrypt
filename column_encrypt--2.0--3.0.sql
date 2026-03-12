/* column_encrypt--2.0--3.0.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION column_encrypt UPDATE TO '3.0'" to load this file. \quit

--
-- Upgrade from 2.0 to 3.0
--
-- Changes in this upgrade:
--   1. Add btree comparison functions for encrypted_text and encrypted_bytea.
--   2. Add ordering operators (<, <=, >=, >) for both encrypted types.
--   3. Add btree operator classes enabling UNIQUE constraints, ORDER BY,
--      and btree indexes on encrypted columns.
--

/*
 * Btree comparison functions (C)
 */

CREATE FUNCTION enc_cmp_enctext(encrypted_text, encrypted_text) RETURNS integer
LANGUAGE c IMMUTABLE STRICT
AS 'column_encrypt', 'enc_btree_cmp_encrted_data';

CREATE FUNCTION enc_cmp_encbytea(encrypted_bytea, encrypted_bytea) RETURNS integer
LANGUAGE c IMMUTABLE STRICT
AS 'column_encrypt', 'enc_btree_cmp_encrted_data';

/*
 * Ordering operator functions for encrypted_text
 */

CREATE FUNCTION enc_lt_enctext(encrypted_text, encrypted_text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT enc_cmp_enctext($1, $2) < 0 $$;

CREATE FUNCTION enc_le_enctext(encrypted_text, encrypted_text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT enc_cmp_enctext($1, $2) <= 0 $$;

CREATE FUNCTION enc_ge_enctext(encrypted_text, encrypted_text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT enc_cmp_enctext($1, $2) >= 0 $$;

CREATE FUNCTION enc_gt_enctext(encrypted_text, encrypted_text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT enc_cmp_enctext($1, $2) > 0 $$;

/*
 * Ordering operator functions for encrypted_bytea
 */

CREATE FUNCTION enc_lt_encbytea(encrypted_bytea, encrypted_bytea) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT enc_cmp_encbytea($1, $2) < 0 $$;

CREATE FUNCTION enc_le_encbytea(encrypted_bytea, encrypted_bytea) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT enc_cmp_encbytea($1, $2) <= 0 $$;

CREATE FUNCTION enc_ge_encbytea(encrypted_bytea, encrypted_bytea) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT enc_cmp_encbytea($1, $2) >= 0 $$;

CREATE FUNCTION enc_gt_encbytea(encrypted_bytea, encrypted_bytea) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT enc_cmp_encbytea($1, $2) > 0 $$;

/*
 * define ordering operators for encrypted text
 */

CREATE OPERATOR < (
PROCEDURE = enc_lt_enctext,
LEFTARG = encrypted_text,
RIGHTARG = encrypted_text,
COMMUTATOR = >,
NEGATOR = >=,
RESTRICT = scalarltsel,
JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
PROCEDURE = enc_le_enctext,
LEFTARG = encrypted_text,
RIGHTARG = encrypted_text,
COMMUTATOR = >=,
NEGATOR = >,
RESTRICT = scalarltsel,
JOIN = scalarltjoinsel
);

CREATE OPERATOR >= (
PROCEDURE = enc_ge_enctext,
LEFTARG = encrypted_text,
RIGHTARG = encrypted_text,
COMMUTATOR = <=,
NEGATOR = <,
RESTRICT = scalargtsel,
JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
PROCEDURE = enc_gt_enctext,
LEFTARG = encrypted_text,
RIGHTARG = encrypted_text,
COMMUTATOR = <,
NEGATOR = <=,
RESTRICT = scalargtsel,
JOIN = scalargtjoinsel
);

/*
 * define ordering operators for encrypted bytea
 */

CREATE OPERATOR < (
PROCEDURE = enc_lt_encbytea,
LEFTARG = encrypted_bytea,
RIGHTARG = encrypted_bytea,
COMMUTATOR = >,
NEGATOR = >=,
RESTRICT = scalarltsel,
JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
PROCEDURE = enc_le_encbytea,
LEFTARG = encrypted_bytea,
RIGHTARG = encrypted_bytea,
COMMUTATOR = >=,
NEGATOR = >,
RESTRICT = scalarltsel,
JOIN = scalarltjoinsel
);

CREATE OPERATOR >= (
PROCEDURE = enc_ge_encbytea,
LEFTARG = encrypted_bytea,
RIGHTARG = encrypted_bytea,
COMMUTATOR = <=,
NEGATOR = <,
RESTRICT = scalargtsel,
JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
PROCEDURE = enc_gt_encbytea,
LEFTARG = encrypted_bytea,
RIGHTARG = encrypted_bytea,
COMMUTATOR = <,
NEGATOR = <=,
RESTRICT = scalargtsel,
JOIN = scalargtjoinsel
);

/*
 * define btree index for encrypted text
 */

CREATE OPERATOR FAMILY btree_text_enc_ops USING btree;

CREATE OPERATOR CLASS btree_text_enc_ops
DEFAULT FOR TYPE encrypted_text USING btree FAMILY btree_text_enc_ops AS
OPERATOR 1 <(encrypted_text,encrypted_text) ,
OPERATOR 2 <=(encrypted_text,encrypted_text) ,
OPERATOR 3 =(encrypted_text,encrypted_text) ,
OPERATOR 4 >=(encrypted_text,encrypted_text) ,
OPERATOR 5 >(encrypted_text,encrypted_text) ,
FUNCTION 1 (encrypted_text, encrypted_text) enc_cmp_enctext(encrypted_text, encrypted_text);

/*
 * define btree index for encrypted binary
 */

CREATE OPERATOR FAMILY btree_bytea_enc_ops USING btree;

CREATE OPERATOR CLASS btree_bytea_enc_ops
DEFAULT FOR TYPE encrypted_bytea USING btree FAMILY btree_bytea_enc_ops AS
OPERATOR 1 <(encrypted_bytea,encrypted_bytea) ,
OPERATOR 2 <=(encrypted_bytea,encrypted_bytea) ,
OPERATOR 3 =(encrypted_bytea,encrypted_bytea) ,
OPERATOR 4 >=(encrypted_bytea,encrypted_bytea) ,
OPERATOR 5 >(encrypted_bytea,encrypted_bytea) ,
FUNCTION 1 (encrypted_bytea, encrypted_bytea) enc_cmp_encbytea(encrypted_bytea, encrypted_bytea);
