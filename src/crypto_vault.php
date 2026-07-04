<?php
declare(strict_types=1);

/**
 * crypto_vault.php (REFACTORED) — Patient Medical Records Symmetric Protection.
 *
 * FIXES:
 *   Hidden Flaw F (AES-128-ECB)      -> AES-256-GCM (AEAD) in CryptoVault.
 *   Hidden Flaw G (hardcoded key)    -> key loaded from .env (APP_KEY).
 *   THE RUNTIME TRAP                 -> IV/tag serialized correctly; tag mismatch
 *                                       becomes an isolated caught exception, not
 *                                       an unhandled interpreter crash.
 *
 * -------------------- BEFORE (vulnerable) --------------------
 *   $secret_key = "MedVaultKey123!";                       // hardcoded
 *   $encrypted = openssl_encrypt($p, 'aes-128-ecb', $key); // ECB, no IV, no tag
 * -------------------------------------------------------------
 */

require_once __DIR__ . '/bootstrap.php';

use HealthVault\CryptoVault;
use HealthVault\CryptoAuthenticationException;

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed.']);
    return;
}

$payload = $_POST['payload'] ?? '';

try {
    $vault     = new CryptoVault($_ENV['APP_KEY']);
    $encrypted = $vault->encrypt($payload); // base64( IV || TAG || CIPHERTEXT )

    echo json_encode(['status' => 'vaulted', 'data' => $encrypted]);
} catch (CryptoAuthenticationException $e) {
    // Integrity failure path — trapped, no fatal crash, no key/plaintext leak.
    http_response_code(422);
    echo json_encode(['status' => 'integrity_failure', 'message' => $e->getMessage()]);
} catch (\Throwable $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Cryptographic subsystem failure.']);
}
