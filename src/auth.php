<?php
declare(strict_types=1);

/**
 * auth.php (REFACTORED) — Staff Key Authentication System.
 *
 * FIXES:
 *   Hidden Flaw D (byte vs character bound) -> mb_strlen() semantic check.
 *   Hidden Flaw E (MD5)                     -> Argon2id verify against DB hash.
 *
 * -------------------- BEFORE (vulnerable) --------------------
 *   if (strlen($inputKey) > 256) { die(...); }          // BYTE length
 *   $stored_hash = "098f6bcd...";                        // hardcoded MD5
 *   if (md5($inputKey) === $stored_hash) { ... }         // broken primitive
 * -------------------------------------------------------------
 */

require_once __DIR__ . '/bootstrap.php';

use HealthVault\Database;
use HealthVault\StaffAuthenticator;

header('Content-Type: text/plain; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo 'Method Not Allowed.';
    return;
}

$username = $_POST['username']  ?? '';
$inputKey = $_POST['auth_key']  ?? '';

$auth = new StaffAuthenticator();

// SEMANTIC BOUND CHECK: character count, not byte count. Multi-byte payloads
// can no longer bypass the limit.
if (!$auth->isWithinBounds($inputKey)) {
    http_response_code(400);
    echo 'Rejected: key exceeds ' . StaffAuthenticator::MAX_KEY_CHARS . ' character bound.';
    return;
}

// Fetch the Argon2id hash for this staff account from the database.
$pdo  = Database::connect();
$stmt = $pdo->prepare(
    'SELECT auth_key_hash FROM staff_credentials WHERE username = :u'
);
$stmt->bindValue(':u', $username, PDO::PARAM_STR);
$stmt->execute();
$stored = $stmt->fetchColumn();

// Generic failure message + verify even on unknown user is out of scope here;
// password_verify() is itself constant-time against the stored hash.
if ($stored !== false && $auth->verify($inputKey, (string) $stored)) {
    echo 'Access Granted.';
} else {
    http_response_code(401);
    echo 'Access Denied.';
}
