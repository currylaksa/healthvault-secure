# HealthVault-Secure

Secure refactoring of the three breach-vector source files from the MediChain
*HealthVault-API* incident — SECR4483/SCSR4483 Secure Programming Alternative
Assessment.

## What was fixed

| File | Legacy flaw | Remediation |
|------|-------------|-------------|
| `search.php`       | **A** SQL Injection (raw concat, root DB) | PDO prepared statement + bound param + least-privilege DB user |
| `search.php`       | **B/C** Reflected XSS | `htmlspecialchars()` context-aware output encoding |
| `auth.php`         | **D** byte-length bound check | `mb_strlen()` semantic character bound |
| `auth.php`         | **E** MD5 hashing | Argon2id (`PASSWORD_ARGON2ID`) + `password_verify()` |
| `crypto_vault.php` | **F** AES-128-ECB | AES-256-GCM (AEAD), unique 12-byte IV, 16-byte tag |
| `crypto_vault.php` | **G** hardcoded key | key loaded from `.env`, `.gitignore`d |

## Layout

```
src/
  search.php                       refactored SQLi/XSS-safe search proxy
  auth.php                         refactored Argon2id auth endpoint
  crypto_vault.php                 refactored AES-256-GCM vault endpoint
  CryptoVault.php                  AEAD encrypt/decrypt (testable class)
  CryptoAuthenticationException.php trapped integrity-failure type
  StaffAuthenticator.php           Argon2id hashing + mb_strlen bound check
  Database.php                     PDO connection factory (env-driven)
  bootstrap.php                    autoload + .env loader
tests/
  CryptoVaultTest.php              untampered lifecycle + tampered-throws-AEAD
  StaffAuthenticatorTest.php       credential hash match + bound checks
bin/
  ecb_vs_gcm_demo.php              ECB leak vs GCM diffusion evidence
  generate_argon2id_seed.php       MD5 -> Argon2id DB migration helper
schema.sql                         database schema + seed data
.env.example                       secret template (real .env is git-ignored)
```

## Quick start

See [SETUP.md](SETUP.md). TL;DR:

```bash
brew install php composer
composer install
cp .env.example .env   # then set APP_KEY + DB creds
./vendor/bin/phpunit --testdox
```
