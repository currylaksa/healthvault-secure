<?php
declare(strict_types=1);

/**
 * ecb_vs_gcm_demo.php — visual proof of ECB pattern leakage vs GCM diffusion.
 *
 * Encrypts two records that share a 16-byte-aligned plaintext prefix.
 * Under AES-128-ECB the shared prefix produces IDENTICAL leading ciphertext
 * blocks (the leak). Under AES-256-GCM the same input produces unrelated
 * ciphertext every time (unique IV -> counter mode). Run:
 *
 *   php bin/ecb_vs_gcm_demo.php
 */

require_once __DIR__ . '/../src/CryptoAuthenticationException.php';
require_once __DIR__ . '/../src/CryptoVault.php';

use HealthVault\CryptoVault;

// Align a shared 16-byte prefix so ECB block boundaries expose the pattern.
$prefix = 'DIAGNOSIS_CANCER';                 // exactly 16 bytes
$recordA = $prefix . 'PATIENT=JohnDoe;STATUS=Critical';
$recordB = $prefix . 'PATIENT=JaneSmith;STATUS=Stable';

$blocks = static function (string $raw): string {
    return implode(' ', str_split(bin2hex($raw), 32)); // 16-byte blocks
};

echo "=== LEGACY AES-128-ECB (leaks pattern) ===\n";
$ecbKey = 'MedVaultKey123!!';                 // 16 bytes for AES-128
$ecbA = openssl_encrypt($recordA, 'aes-128-ecb', $ecbKey, OPENSSL_RAW_DATA);
$ecbB = openssl_encrypt($recordB, 'aes-128-ecb', $ecbKey, OPENSSL_RAW_DATA);
echo "A: " . $blocks($ecbA) . "\n";
echo "B: " . $blocks($ecbB) . "\n";
echo "First block identical? " .
    (substr($ecbA, 0, 16) === substr($ecbB, 0, 16) ? "YES  <-- LEAK\n" : "no\n");

echo "\n=== SECURE AES-256-GCM (no pattern) ===\n";
$vault = new CryptoVault(base64_encode(str_repeat("\x02", 32)));
$gcmA = base64_decode($vault->encrypt($recordA), true);
$gcmB = base64_decode($vault->encrypt($recordB), true);
// Skip 12-byte IV + 16-byte tag header to compare ciphertext bodies.
echo "A: " . $blocks(substr($gcmA, 28)) . "\n";
echo "B: " . $blocks(substr($gcmB, 28)) . "\n";
echo "First block identical? " .
    (substr($gcmA, 28, 16) === substr($gcmB, 28, 16) ? "YES\n" : "no   <-- SECURE\n");
