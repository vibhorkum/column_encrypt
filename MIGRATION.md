# Migration Guide: v3.x to v4.0

This guide covers the migration path from column_encrypt v3.x to v4.0.

## Overview

v4.0 is a major simplification that removes deprecated features and provides a clean, minimal API. The migration path is:

```
v3.1 → v3.3 (deprecation release) → v4.0 (clean release)
```

**Important**: You cannot upgrade directly from v3.1 to v4.0. You must go through v3.3 first.

## What's Removed in v4.0

### Functions Removed
- `cipher_key_disable_log()` / `cipher_key_enable_log()` - Now automatic
- `register_cipher_key()` - Use `encrypt.register_key()`
- `load_key()` / `load_key_by_version()` - Use `encrypt.load_key()`
- `rm_key_details()` - Use `encrypt.unload_key()`
- `activate_cipher_key()` / `revoke_cipher_key()` - Use `encrypt.activate_key()` / `encrypt.revoke_key()`
- `cipher_key_versions()` - Use `encrypt.keys()`
- `cipher_key_reencrypt_data*()` - Use `encrypt.rotate()`
- `cipher_verify_column_encryption()` - Use `encrypt.verify()`
- `cipher_metrics()` / `cipher_encryption_stats()` / `cipher_key_usage_stats()`
- `cipher_coverage_audit()` / `cipher_coverage_summary()`
- `cipher_start_rotation_job()` and all rotation job functions
- `cipher_key_audit_log_view()` / `cipher_key_check_expired()`
- `is_key_loaded()` - Use `encrypt.status()`
- `cipher_key_logical_replication_check()`

### Tables Removed
- `cipher_key_audit_log`
- `cipher_key_failed_attempts`
- `cipher_rotation_jobs`

### Roles Simplified
The 3-role system (`column_encrypt_admin`, `column_encrypt_runtime`, `column_encrypt_reader`) is replaced by a single `column_encrypt_user` role.

## Step 1: Upgrade to v3.3

v3.3 introduces the new `encrypt.*` API while keeping old functions available with deprecation notices.

```sql
ALTER EXTENSION column_encrypt UPDATE TO '3.3';
```

## Step 2: Update Your Code

Replace old function calls with the new API:

### Key Registration

**Before (v3.1):**
```sql
SELECT cipher_key_disable_log();
SELECT register_cipher_key('my-dek', 'aes', 'my-passphrase');
SELECT cipher_key_enable_log();
```

**After (v3.3+):**
```sql
-- Log masking is automatic
SELECT encrypt.register_key('my-dek', 'my-passphrase');
```

### Key Loading

**Before (v3.1):**
```sql
SELECT load_key('my-passphrase');
-- or
SELECT load_key_by_version('my-passphrase', 2);
```

**After (v3.3+):**
```sql
SELECT encrypt.load_key('my-passphrase');
-- or for all versions (needed during rotation):
SELECT encrypt.load_key('my-passphrase', all_versions => true);
```

### Key Unloading

**Before (v3.1):**
```sql
SELECT rm_key_details();
```

**After (v3.3+):**
```sql
SELECT encrypt.unload_key();
```

### Key Activation/Revocation

**Before (v3.1):**
```sql
SELECT activate_cipher_key(2);
SELECT revoke_cipher_key(3);
```

**After (v3.3+):**
```sql
SELECT encrypt.activate_key(2);
SELECT encrypt.revoke_key(3);
```

### Viewing Keys

**Before (v3.1):**
```sql
SELECT * FROM cipher_key_versions();
```

**After (v3.3+):**
```sql
SELECT * FROM encrypt.keys();
```

### Key Rotation

**Before (v3.1):**
```sql
SELECT cipher_key_reencrypt_data('public', 'mytable', 'secret_col');
-- or batch:
SELECT cipher_key_reencrypt_data_batch('public', 'mytable', 'secret_col', 1000);
```

**After (v3.3+):**
```sql
SELECT encrypt.rotate('public', 'mytable', 'secret_col');
-- Batch limit:
SELECT encrypt.rotate('public', 'mytable', 'secret_col', 1000);
```

### Verification

**Before (v3.1):**
```sql
SELECT * FROM cipher_verify_column_encryption('public', 'mytable', 'secret_col');
```

**After (v3.3+):**
```sql
SELECT * FROM encrypt.verify('public', 'mytable', 'secret_col');
```

### Status Check

**Before (v3.1):**
```sql
SELECT is_key_loaded();
SELECT * FROM cipher_key_versions();
```

**After (v3.3+):**
```sql
SELECT * FROM encrypt.status();
```

## Step 3: Update Role Grants

**Important**: The v4.0 upgrade **revokes permissions** from the legacy 3-role system (`column_encrypt_admin`, `column_encrypt_runtime`, `column_encrypt_reader`). You must complete this step **before** upgrading to v4.0.

If you were using the 3-role system, migrate to the unified role:

```sql
-- Old way: different roles for different operations
GRANT column_encrypt_admin TO key_manager;
GRANT column_encrypt_runtime TO app_user;
GRANT column_encrypt_reader TO auditor;

-- New way: single role for all encryption operations
GRANT column_encrypt_user TO key_manager;
GRANT column_encrypt_user TO app_user;

-- For read-only access (auditors), grant only metadata functions:
GRANT USAGE ON SCHEMA encrypt TO auditor;
GRANT EXECUTE ON FUNCTION encrypt.keys() TO auditor;
GRANT EXECUTE ON FUNCTION encrypt.status() TO auditor;
```

**Note**: The legacy roles themselves are not dropped (to preserve any existing `GRANT role TO user` chains), but their permissions on `encrypt.*` functions are revoked during the v4.0 upgrade.

## Step 4: Upgrade to v4.0

Once your code uses only `encrypt.*` functions:

```sql
ALTER EXTENSION column_encrypt UPDATE TO '4.0';
```

This removes all deprecated functions. Any code still using old functions will fail.

## API Reference (v4.0)

| Function | Description |
|----------|-------------|
| `encrypt.register_key(dek, passphrase, [activate])` | Register new encryption key |
| `encrypt.load_key(passphrase, [all_versions])` | Load key(s) into session |
| `encrypt.unload_key()` | Clear keys from session |
| `encrypt.activate_key(key_id)` | Set active key for new encryptions |
| `encrypt.revoke_key(key_id)` | Prevent key from being loaded |
| `encrypt.rotate(schema, table, column, [batch_size])` | Re-encrypt with active key |
| `encrypt.verify(schema, table, column, [sample_size])` | Verify encryption integrity |
| `encrypt.keys()` | List all registered keys |
| `encrypt.status()` | Quick status: loaded keys, active key, column count |
| `encrypt.blind_index(value, hmac_key)` | Create searchable blind index |

## Rollback

If you need to rollback from v4.0 to v3.3:

1. You cannot downgrade the extension version directly
2. You must `DROP EXTENSION` and recreate from backup
3. Or restore from a database backup taken before upgrade

**Recommendation**: Take a full database backup before upgrading to v4.0.

## Troubleshooting

### "function cipher_key_disable_log() does not exist"

You're running v4.0 code with old API calls. Update your code to use `encrypt.*` functions.

### "permission denied for function encrypt.register_key"

Grant the unified role to your user:
```sql
GRANT column_encrypt_user TO your_role;
```

### "incorrect passphrase" (SQLSTATE 28P01)

The passphrase doesn't match. Ensure you're using the correct KEK (passphrase) that was used to wrap the DEK during `encrypt.register_key()`.

**Note**: In v4.0, the error message is `incorrect passphrase` with SQLSTATE `28P01` (condition name: `invalid_password`). Legacy versions used `EDB-ENC0012: incorrect decryption key`.
