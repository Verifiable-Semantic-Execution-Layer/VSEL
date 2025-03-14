# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in VSEL, please report it responsibly.

**Do NOT open a public issue for security vulnerabilities.**

Contact the maintainers directly with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment

## Security Model

VSEL implements hybrid classical + post-quantum cryptography (PQC).
All cryptographic operations use domain separation.
See `docs/CRYPTOGRAPHIC_MODEL.md` and `docs/THREAT_MODEL.md` for details.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
