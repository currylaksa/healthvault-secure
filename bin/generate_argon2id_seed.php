<?php
declare(strict_types=1);

/**
 * generate_argon2id_seed.php
 *
 * Migration helper: prints an UPDATE script that replaces the legacy MD5 hashes
 * in staff_credentials with Argon2id hashes. Run once to migrate the demo DB.
 *
 * Usage:
 *   php bin/generate_argon2id_seed.php > migrate_argon2id.sql
 *   /Applications/XAMPP/xamppfiles/bin/mysql medic_vault_db < migrate_argon2id.sql
 */

require_once __DIR__ . '/../vendor/autoload.php';

use HealthVault\StaffAuthenticator;

$auth = new StaffAuthenticator();

// Original plaintext keys documented in schema.sql seed comments.
$credentials = [
    'dr_faizal'   => 'testkey123',
    'dr_sharifah' => 'doctorsecret',
];

echo "-- Argon2id migration for staff_credentials (replaces legacy MD5).\n";
echo "USE `medic_vault_db`;\n";
foreach ($credentials as $username => $plainKey) {
    $hash = $auth->hash($plainKey);
    printf(
        "UPDATE `staff_credentials` SET `auth_key_hash` = '%s' WHERE `username` = '%s';\n",
        $hash,
        $username
    );
}
