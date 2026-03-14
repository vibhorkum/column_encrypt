# Security Review Checklist

## Secret handling

- [ ] No plaintext keys logged
- [ ] No decrypted values logged
- [ ] No sensitive data exposed in errors
- [ ] Sensitive buffers handled carefully
- [ ] Avoid unnecessary copies of secret material

## Input validation

- [ ] All lengths validated
- [ ] All pointers validated
- [ ] Malformed ciphertext rejected safely
- [ ] Header/version parsing is strict
- [ ] NULL handling is correct

## PostgreSQL-specific safety

- [ ] Varlena handling is correct
- [ ] Datum conversions are correct
- [ ] Memory context usage is safe
- [ ] Error reporting does not leak secrets

## Upgrade safety

- [ ] SQL object changes reflected in upgrade scripts
- [ ] Existing upgrade paths preserved
- [ ] User-visible behavior changes documented

## Tests

- [ ] Regression added for bug fixes
- [ ] Failure-path tests included where practical
- [ ] Install and upgrade tested
