<?php
declare(strict_types=1);

namespace HealthVault;

/**
 * CryptoVault — Authenticated symmetric protection for patient medical records.
 *
 * SECURITY DESIGN (Chapter 3 / Question 3):
 *   - Cipher: AES-256-GCM (AEAD). Replaces legacy AES-128-ECB.
 *       * ECB is deterministic: identical plaintext blocks -> identical ciphertext
 *         blocks, leaking structural patterns (see repeating "Stage-2 Carcinoma"
 *         rows in schema.sql). GCM is a counter-mode stream cipher, so identical
 *         plaintext never yields identical ciphertext given a unique IV.
 *   - Key: 32 raw bytes (256-bit) loaded from the runtime environment (.env),
 *     never hardcoded (fixes Hidden Flaw G).
 *   - IV: fresh 12-byte (96-bit) nonce per encryption via random_bytes(). 96 bits
 *     is the GCM-optimal nonce width. IVs are NEVER reused with the same key —
 *     reuse collapses GCM security (nonce-misuse leaks the auth key stream).
 *   - Tag: 16-byte (128-bit) GCM authentication tag binds ciphertext integrity.
 *     On decryption a mismatched tag makes openssl_decrypt() return false; we
 *     convert that into an isolated, catchable exception rather than allowing an
 *     unhandled runtime failure to crash the interpreter (fixes THE RUNTIME TRAP).
 *
 * WIRE / SERIALIZATION FORMAT (packed, then base64 for safe transport):
 *
 *     [ 12-byte IV ][ 16-byte TAG ][ N-byte CIPHERTEXT ]
 *     |<-- header 28 bytes -->|<-- variable payload -->|
 *
 * base64_encode() wraps the raw envelope so it survives JSON / HTTP transport.
 */
final class CryptoVault
{
    private const CIPHER   = 'aes-256-gcm';
    private const IV_LEN   = 12;  // 96-bit GCM nonce
    private const TAG_LEN  = 16;  // 128-bit GCM auth tag
    private const KEY_LEN  = 32;  // 256-bit key

    private string $key;

    /**
     * @param string $base64Key Base64-encoded 32-byte key (from APP_KEY in .env).
     * @throws \InvalidArgumentException if the key is missing or the wrong length.
     */
    public function __construct(string $base64Key)
    {
        $raw = base64_decode($base64Key, true);
        if ($raw === false || strlen($raw) !== self::KEY_LEN) {
            throw new \InvalidArgumentException(
                'APP_KEY must be a base64-encoded 32-byte (256-bit) key.'
            );
        }
        $this->key = $raw;
    }

    /**
     * Encrypt a plaintext medical payload.
     *
     * @return string base64( IV || TAG || CIPHERTEXT )
     * @throws \RuntimeException if the underlying cipher operation fails.
     */
    public function encrypt(string $plaintext): string
    {
        $iv  = random_bytes(self::IV_LEN);          // unique nonce per call
        $tag = '';                                   // filled by reference below

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',                 // no additional authenticated data (AAD)
            self::TAG_LEN
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed.');
        }

        // Pack header + payload, then base64 for transport safety.
        return base64_encode($iv . $tag . $ciphertext);
    }

    /**
     * Decrypt and verify an envelope produced by encrypt().
     *
     * @throws CryptoAuthenticationException on tag mismatch / tampering / truncation.
     */
    public function decrypt(string $envelope): string
    {
        $raw = base64_decode($envelope, true);
        if ($raw === false || strlen($raw) < self::IV_LEN + self::TAG_LEN) {
            throw new CryptoAuthenticationException('Malformed or truncated ciphertext envelope.');
        }

        // Unpack the three fields by their fixed offsets.
        $iv         = substr($raw, 0, self::IV_LEN);
        $tag        = substr($raw, self::IV_LEN, self::TAG_LEN);
        $ciphertext = substr($raw, self::IV_LEN + self::TAG_LEN);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        // AEAD contract: false => authentication failed (tampered cipher/tag/IV).
        // We isolate the failure as a domain exception; the caller decides policy.
        if ($plaintext === false) {
            throw new CryptoAuthenticationException(
                'Authentication tag mismatch: payload integrity verification failed.'
            );
        }

        return $plaintext;
    }
}
