/* column_encrypt--3.3--4.0.sql */

-- Upgrade script: Clean API Release
--
-- v4.0 removes all deprecated features and provides only the simplified API.
--
-- REMOVED in v4.0:
-- - cipher_key_disable_log() / cipher_key_enable_log()
-- - register_cipher_key() (use encrypt.register_key)
-- - load_key() / load_key_by_version() (use encrypt.load_key)
-- - rm_key_details() (use encrypt.unload_key)
-- - activate_cipher_key() / revoke_cipher_key()
-- - cipher_key_versions() (use encrypt.keys)
-- - cipher_key_reencrypt_data*() (use encrypt.rotate)
-- - cipher_verify_column_encryption() (use encrypt.verify)
-- - cipher_key_audit_log table and functions
-- - Rate limiting tables and functions
-- - Coverage audit functions
-- - Rotation job scheduler
-- - Monitoring/metrics functions
-- - 3-role system (replaced by column_encrypt_user)
--
-- MIGRATION: Update your code to use encrypt.* functions before upgrading.

\echo Use "ALTER EXTENSION column_encrypt UPDATE TO '4.0'" to load this file. \quit

/*
 * =============================================================================
 * REMOVE DEPRECATED FUNCTIONS
 * =============================================================================
 */

-- Key management (old API)
DROP FUNCTION IF EXISTS cipher_key_disable_log();
DROP FUNCTION IF EXISTS cipher_key_enable_log();
DROP FUNCTION IF EXISTS register_cipher_key(text, text, text);
DROP FUNCTION IF EXISTS register_cipher_key(text, text, text, integer, boolean, timestamptz, text);
DROP FUNCTION IF EXISTS load_key(text);
DROP FUNCTION IF EXISTS load_key_by_version(text, integer);
DROP FUNCTION IF EXISTS rm_key_details();
DROP FUNCTION IF EXISTS activate_cipher_key(integer);
DROP FUNCTION IF EXISTS revoke_cipher_key(integer);
DROP FUNCTION IF EXISTS cipher_key_versions();
DROP FUNCTION IF EXISTS cipher_key_reencrypt_data(text, text, text);
DROP FUNCTION IF EXISTS cipher_key_reencrypt_data(text, text, text, integer);
DROP FUNCTION IF EXISTS cipher_key_reencrypt_data_batch(text, text, text, integer);
DROP FUNCTION IF EXISTS cipher_verify_column_encryption(text, text, text, integer);

-- Audit logging
DROP FUNCTION IF EXISTS cipher_key_audit_log_view(integer, integer);
DROP FUNCTION IF EXISTS cipher_key_check_expired();
DROP TABLE IF EXISTS cipher_key_audit_log;

-- Rate limiting (if exists from v3.2 or manual install)
DROP FUNCTION IF EXISTS cipher_key_is_locked_out(name);
DROP FUNCTION IF EXISTS cipher_key_record_failed_attempt(name);
DROP FUNCTION IF EXISTS cipher_key_clear_failed_attempts(name);
DROP FUNCTION IF EXISTS cipher_key_unlock_user(name);
DROP FUNCTION IF EXISTS cipher_key_lockout_status();
DROP FUNCTION IF EXISTS cipher_key_rate_limit_config();
DROP TABLE IF EXISTS cipher_key_failed_attempts;

-- Coverage audit
DROP FUNCTION IF EXISTS cipher_coverage_audit(text);
DROP FUNCTION IF EXISTS cipher_coverage_summary(text);

-- Rotation job scheduler
DROP FUNCTION IF EXISTS cipher_start_rotation_job(text, text, text, integer, integer, integer);
DROP FUNCTION IF EXISTS cipher_process_rotation_batch(bigint);
DROP FUNCTION IF EXISTS cipher_run_rotation_job(bigint);
DROP FUNCTION IF EXISTS cipher_pause_rotation_job(bigint);
DROP FUNCTION IF EXISTS cipher_resume_rotation_job(bigint);
DROP FUNCTION IF EXISTS cipher_cancel_rotation_job(bigint);
DROP FUNCTION IF EXISTS cipher_rotation_progress();
DROP TABLE IF EXISTS cipher_rotation_jobs;

-- Monitoring/metrics
DROP FUNCTION IF EXISTS cipher_encryption_stats();
DROP FUNCTION IF EXISTS cipher_key_usage_stats();
DROP FUNCTION IF EXISTS cipher_metrics();
DROP FUNCTION IF EXISTS is_key_loaded();
DROP FUNCTION IF EXISTS cipher_dump_warnings(text);
DROP FUNCTION IF EXISTS cipher_pre_dump_check(text, boolean);
DROP FUNCTION IF EXISTS cipher_guc_reference();
DROP FUNCTION IF EXISTS cipher_status();

-- Replication check
DROP FUNCTION IF EXISTS cipher_key_logical_replication_check(text, text);

-- Internal/legacy functions that were exposed
DROP FUNCTION IF EXISTS enc_store_prv_key(text, text);
DROP FUNCTION IF EXISTS enc_rm_prv_key();

/*
 * =============================================================================
 * CLEAN UP ROLES
 * =============================================================================
 * Keep column_encrypt_user as the canonical role.
 * Old roles are NOT dropped (would break existing grants) but revoked new permissions.
 */

-- Ensure new role exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'column_encrypt_user') THEN
        EXECUTE 'CREATE ROLE column_encrypt_user NOLOGIN';
    END IF;
END;
$$;

/*
 * =============================================================================
 * REVOKE PUBLIC EXECUTION ON INTERNAL FUNCTIONS
 * =============================================================================
 */

REVOKE EXECUTE ON FUNCTION enc_store_key(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION enc_rm_key() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pgstat_actv_mask() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION loaded_cipher_key_versions() FROM PUBLIC;

/*
 * =============================================================================
 * UPDATE COMMENTS
 * =============================================================================
 */

COMMENT ON SCHEMA encrypt IS
    'Column encryption API - register keys, load, rotate, verify';

COMMENT ON TYPE encrypted_text IS
    'Encrypted text type. Use encrypt.load_key() before accessing data.';

COMMENT ON TYPE encrypted_bytea IS
    'Encrypted bytea type. Use encrypt.load_key() before accessing data.';

COMMENT ON TABLE cipher_key_table IS
    'Wrapped encryption keys. Access via encrypt.keys() function.';

-- Remove deprecation comments since functions are gone
COMMENT ON FUNCTION encrypt.register_key(TEXT, TEXT, BOOLEAN) IS
    'Registers a new encryption key. Returns the assigned key ID.';

COMMENT ON FUNCTION encrypt.load_key(TEXT, BOOLEAN) IS
    'Loads encryption key(s) into session memory. Use all_versions=true for rotation.';

COMMENT ON FUNCTION encrypt.unload_key() IS
    'Clears all encryption keys from session memory.';

COMMENT ON FUNCTION encrypt.activate_key(INTEGER) IS
    'Makes the specified key version the active key for new encryptions.';

COMMENT ON FUNCTION encrypt.revoke_key(INTEGER) IS
    'Revokes a key version, preventing it from being loaded.';

COMMENT ON FUNCTION encrypt.rotate(TEXT, TEXT, TEXT, INTEGER) IS
    'Re-encrypts column data with the current active key. Returns row count.';

COMMENT ON FUNCTION encrypt.verify(TEXT, TEXT, TEXT, INTEGER) IS
    'Verifies encrypted data can be decrypted with loaded keys.';

COMMENT ON FUNCTION encrypt.keys() IS
    'Lists all registered encryption keys with state and usage.';

COMMENT ON FUNCTION encrypt.status() IS
    'Returns current encryption status: key loaded, active key, column count.';

COMMENT ON FUNCTION encrypt.blind_index(TEXT, TEXT) IS
    'Creates HMAC-SHA256 blind index for searchable encryption.';
