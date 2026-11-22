# Security

For vulnerability reporting and the intentional lab design on `main` vs `vulnerable`, see [docs/SECURITY.md](docs/SECURITY.md).

## Quick report

Email **json.c.morgan@gmail.com**. Do not open public issues for exploitable behaviour on production deployments you do not own.

## CI

Every push runs gitleaks, ruff, and pytest (see `.github/workflows/ci.yml`).