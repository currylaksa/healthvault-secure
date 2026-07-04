# Setup Guide (macOS)

Your XAMPP PHP 8.0 was **compiled without Argon2id**, which the assignment
mandates. Install a modern PHP (Argon2id + OpenSSL GCM built in) and Composer via
Homebrew, then run the suite.

## 1. Install PHP 8.2+ and Composer

```bash
brew install php composer
```

Homebrew PHP ships with `PASSWORD_ARGON2ID`. Confirm you are using it (not XAMPP):

```bash
which php                 # expect /opt/homebrew/bin/php
php -v                    # expect PHP 8.2+ (or newer)
php -r 'var_dump(defined("PASSWORD_ARGON2ID"));'   # expect bool(true)
```

If `which php` still points at XAMPP, prepend Homebrew to PATH for this shell:

```bash
export PATH="/opt/homebrew/bin:$PATH"
```

## 2. Install dependencies

```bash
cd healthvault-secure
composer install
```

This pulls `vlucas/phpdotenv` and `phpunit/phpunit` into `vendor/`.

## 3. Configure secrets

```bash
cp .env.example .env
php -r 'echo "APP_KEY=".base64_encode(random_bytes(32)).PHP_EOL;' >> .env
# then edit .env: set DB_USER / DB_PASS for your MySQL, and remove the duplicate
# empty APP_KEY= line left from .env.example.
```

## 4. Initialize the database (XAMPP MySQL is fine for the DB)

```bash
/Applications/XAMPP/xamppfiles/bin/mysql -u root < schema.sql

# migrate the legacy MD5 seeds to Argon2id for the auth.php demo:
php bin/generate_argon2id_seed.php > migrate_argon2id.sql
/Applications/XAMPP/xamppfiles/bin/mysql -u root < migrate_argon2id.sql
```

Create a least-privilege app account (do NOT use root — that is what turned the
SQLi into a full dump):

```sql
CREATE USER 'medivault_app'@'127.0.0.1' IDENTIFIED BY 'choose-a-password';
GRANT SELECT, INSERT ON medic_vault_db.* TO 'medivault_app'@'127.0.0.1';
FLUSH PRIVILEGES;
```

Put those credentials in `.env`.

## 5. Run the tests (this is the live demo for the video)

```bash
./vendor/bin/phpunit --testdox
```

Expect all assertions green (untampered lifecycle, tampered-throws-AEAD,
credential-hash-matches, bound checks).

## 6. Supporting demos

```bash
php bin/ecb_vs_gcm_demo.php     # visual ECB pattern leak vs GCM diffusion
```

## 7. Serve the endpoints (optional manual testing)

```bash
php -S 127.0.0.1:8000 -t src
# then, e.g.:
curl 'http://127.0.0.1:8000/search.php?keyword=John'
curl -X POST http://127.0.0.1:8000/crypto_vault.php -d 'payload=secret record'
```
