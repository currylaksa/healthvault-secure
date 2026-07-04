<?php
declare(strict_types=1);

namespace HealthVault\Tests;

use HealthVault\CryptoVault;
use HealthVault\CryptoAuthenticationException;
use PHPUnit\Framework\TestCase;

/**
 * Verifies the AES-256-GCM authenticated encryption lifecycle.
 *
 * Covers assignment Question 3 assertions:
 *   (1) untampered cryptographic lifecycle  -> roundtrip returns original
 *   (2) tampered ciphertext execution path  -> throws an AEAD exception
 */
final class CryptoVaultTest extends TestCase
{
    private CryptoVault $vault;

    protected function setUp(): void
    {
        // Deterministic 32-byte test key (base64). NOT a production secret.
        $this->vault = new CryptoVault(base64_encode(str_repeat("\x01", 32)));
    }

    /** ASSERTION 1: a clean encrypt -> decrypt cycle recovers the exact plaintext. */
    public function testUntamperedLifecycleRoundTrips(): void
    {
        $plaintext = 'DIAGNOSIS: Stage-2 Carcinoma. TREATMENT: Chemotherapy cycle 1.';

        $envelope  = $this->vault->encrypt($plaintext);
        $recovered = $this->vault->decrypt($envelope);

        $this->assertSame($plaintext, $recovered);
    }

    /** ASSERTION 2: flipping a ciphertext byte makes the GCM tag check fail. */
    public function testTamperedCiphertextThrowsAeadException(): void
    {
        $envelope = $this->vault->encrypt('controlled substance dosage: 5mg');

        // Corrupt one byte inside the ciphertext body (offset past IV+TAG header).
        $raw       = base64_decode($envelope, true);
        $raw[30]   = $raw[30] ^ "\xFF"; // flip bits of a payload byte
        $tampered  = base64_encode($raw);

        $this->expectException(CryptoAuthenticationException::class);
        $this->vault->decrypt($tampered);
    }

    /** GCM non-determinism: identical plaintext yields distinct envelopes (unique IV). */
    public function testIdenticalPlaintextProducesDistinctCiphertext(): void
    {
        $a = $this->vault->encrypt('Stage-2 Carcinoma');
        $b = $this->vault->encrypt('Stage-2 Carcinoma');

        $this->assertNotSame($a, $b, 'Unique IV per encryption must prevent ECB-style pattern leakage.');
    }

    /** A truncated envelope is rejected as an integrity failure, not a crash. */
    public function testTruncatedEnvelopeThrowsAeadException(): void
    {
        $this->expectException(CryptoAuthenticationException::class);
        $this->vault->decrypt(base64_encode('too-short'));
    }
}
