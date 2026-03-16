# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- DEK minimum length validation (16 bytes) for cryptographic strength
- Additional regression tests for NULL handling, equality comparison, and hash consistency
- Network byte order (big-endian) for key version header to ensure cross-platform compatibility
- `encrypt.enable` check in `cipher_key_reencrypt_data(text, text, text)` for consistency with batch version
- Error code reference documentation in README

### Changed
- Key version header now uses network byte order (big-endian) instead of native endianness

### Fixed
- Missing `encrypt.enable` check in full re-encryption function

## [3.0] - 2025-03-01

### Added
- Role-based access control with `column_encrypt_admin`, `column_encrypt_runtime`, and `column_encrypt_reader` roles
- Key lifecycle states: `pending`, `active`, `retired`, `revoked`
- `key_version` column and versioned key management in `cipher_key_table`
- `load_key_by_version()` for loading specific key versions
- `activate_cipher_key()` and `revoke_cipher_key()` for key state management
- `cipher_key_versions()` for listing registered keys and their metadata
- `cipher_key_reencrypt_data()` and `cipher_key_reencrypt_data_batch()` for key rotation
- `cipher_key_logical_replication_check()` for replication readiness assessment
- `column_encrypt_blind_index_text()` and `column_encrypt_blind_index_bytea()` for blind indexing
- `loaded_cipher_key_versions()` for session keyring introspection
- `enc_key_version()` to extract key version from encrypted values
- Equality and hash semantics on decrypted plaintext (breaking change from 2.0)
- Row-level security on `cipher_key_table`
- Docker-based logical replication test harness

### Changed
- Renamed `key` column to `wrapped_key` in `cipher_key_table`
- Hash functions now operate on decrypted plaintext instead of ciphertext
- Equality comparisons now operate on decrypted plaintext
- REVOKE execute from PUBLIC on all sensitive functions

### Fixed
- Log hook chaining order (prior hooks run first, masking is applied last)

### Upgrade Notes
- After upgrading, REINDEX any hash indexes on encrypted columns
- For scalable equality lookups, prefer companion blind-index columns

## [2.0] - 2024-06-01

### Added
- Two-tier key model (KEK/DEK) with `pgp_sym_encrypt`/`pgp_sym_decrypt`
- `register_cipher_key()` with master passphrase wrapping
- `load_key()` for session key loading
- Key version header (2 bytes) prepended to all ciphertext
- `cipher_key_disable_log()` and `cipher_key_enable_log()` for log suppression
- Log masking via `emit_log_hook` for sensitive function calls

### Changed
- Encryption keys now stored wrapped (encrypted) in database
- Session keys held in `TopMemoryContext` with secure zeroing

## [1.0] - 2024-01-01

### Added
- Initial release
- `encrypted_text` and `encrypted_bytea` custom types
- Transparent encryption/decryption via type I/O functions
- `encrypt.enable` GUC for global enable/disable
- `pgcrypto` integration for AES encryption
- Basic equality operators
- Hash operator classes for hash indexes
- Type casts from `bool`, `inet`, `cidr`, `xml`, `character`
