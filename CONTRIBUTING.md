# Contributing to column_encrypt

Thank you for considering contributing to column_encrypt! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- PostgreSQL development headers (`postgresql-server-dev-*` on Debian/Ubuntu, `postgresql-devel` on RHEL/CentOS)
- C compiler (gcc or clang)
- Make
- Docker (optional, for containerized testing)

### Building from Source

```bash
git clone https://github.com/vibhorkum/column_encrypt.git
cd column_encrypt
make
sudo make install
```

### Running Tests

Run the regression test suite:

```bash
# Using Docker (recommended)
./run-docker-regression.sh 18

# Or directly if PostgreSQL is installed locally
make installcheck
```

Run logical replication tests:

```bash
./run-docker-logical-replication.sh 18
```

## Development Guidelines

### Code Style

- Follow PostgreSQL coding conventions for C code
- Use tabs for indentation in C files
- Use 4 spaces for indentation in SQL files
- Keep lines under 80 characters where practical

### Security Considerations

Before submitting changes, review the [Security Review Checklist](.github/SECURITY_REVIEW_CHECKLIST.md):

- No plaintext keys or passphrases in logs
- All input lengths validated
- Memory properly zeroed after use for sensitive data
- Error messages do not leak sensitive information

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in imperative mood (Add, Fix, Update, Remove)
- Reference issue numbers when applicable

Example:
```
Fix DEK minimum length validation

Add check to reject cipher keys shorter than 16 bytes
to ensure AES-128 minimum security.

Fixes #123
```

### Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes with appropriate tests
3. Ensure all tests pass locally
4. Update documentation if needed
5. Submit a pull request with a clear description

### Testing Requirements

- All new features must include regression tests
- Bug fixes should include a test that reproduces the bug
- Tests should cover both success and failure paths
- Use the Docker harness for consistent test environments

## Reporting Issues

When reporting bugs, please include:

- PostgreSQL version
- Operating system and version
- Steps to reproduce the issue
- Expected vs actual behavior
- Relevant log output (with sensitive data redacted)

## Security Vulnerabilities

If you discover a security vulnerability, please do NOT open a public issue. Instead, email the maintainers directly with details of the vulnerability.

## License

By contributing to column_encrypt, you agree that your contributions will be licensed under the PostgreSQL License.
