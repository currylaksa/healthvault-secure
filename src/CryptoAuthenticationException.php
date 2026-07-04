<?php
declare(strict_types=1);

namespace HealthVault;

/**
 * Thrown when an AEAD decryption fails its integrity check (tag mismatch,
 * tampered ciphertext, wrong key, or truncated envelope).
 *
 * Existing as a dedicated type lets the test suite and callers distinguish an
 * ANTICIPATED, trapped security exception from an unhandled interpreter crash.
 */
final class CryptoAuthenticationException extends \RuntimeException
{
}
