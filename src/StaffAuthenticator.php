<?php
declare(strict_types=1);

namespace HealthVault;

/**
 * StaffAuthenticator — Staff key hashing & verification.
 *
 * SECURITY DESIGN (Chapter 2 / Question 2):
 *   - Bound check uses mb_strlen() (semantic CHARACTER count) instead of the
 *     legacy strlen() (raw BYTE count). Fixes Hidden Flaw D: a multi-byte UTF-8
 *     payload inflates byte length, so a byte-based limit either rejects valid
 *     short strings or is gamed to smuggle oversized inputs -> memory pressure.
 *   - Hashing uses Argon2id (PASSWORD_ARGON2ID) with explicit memory-hardness
 *     and time-hardness parameters. Fixes Hidden Flaw E (MD5). MD5 is fast and
 *     collision-broken; a commodity GPU tries billions of MD5s/sec. Argon2id is
 *     memory-hard: each guess must allocate MEMORY_COST KiB, which starves the
 *     massive parallelism of GPU/ASIC cracking rigs and flattens offline
 *     dictionary pipelines.
 *   - Verification uses password_verify(), which is constant-time and reads the
 *     algorithm + parameters embedded in the stored hash string.
 */
final class StaffAuthenticator
{
    /** Semantic upper bound on key length, in CHARACTERS (not bytes). */
    public const MAX_KEY_CHARS = 256;

    /**
     * Argon2id cost parameters. Tune per deployment hardware.
     *   memory_cost : KiB of memory each hash must occupy (memory-hardness).
     *   time_cost   : number of iterations (time-hardness).
     *   threads     : degree of parallelism.
     */
    private const OPTIONS = [
        'memory_cost' => 65536, // 64 MiB
        'time_cost'   => 4,
        'threads'     => 2,
    ];

    /**
     * Validate the semantic length boundary of an incoming key.
     * Rejects on character count, so multi-byte payloads cannot bypass it.
     */
    public function isWithinBounds(string $inputKey): bool
    {
        return mb_strlen($inputKey, 'UTF-8') <= self::MAX_KEY_CHARS;
    }

    /**
     * Produce an Argon2id hash for storage in staff_credentials.auth_key_hash.
     */
    public function hash(string $inputKey): string
    {
        return password_hash($inputKey, PASSWORD_ARGON2ID, self::OPTIONS);
    }

    /**
     * Constant-time verification against a stored Argon2id hash.
     */
    public function verify(string $inputKey, string $storedHash): bool
    {
        return password_verify($inputKey, $storedHash);
    }
}
