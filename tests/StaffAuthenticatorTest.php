<?php
declare(strict_types=1);

namespace HealthVault\Tests;

use HealthVault\StaffAuthenticator;
use PHPUnit\Framework\TestCase;

/**
 * Verifies Argon2id credential hashing + semantic bound checking.
 *
 * Covers assignment Question 3 assertion:
 *   (3) credential hash integrity matches
 */
final class StaffAuthenticatorTest extends TestCase
{
    private StaffAuthenticator $auth;

    protected function setUp(): void
    {
        $this->auth = new StaffAuthenticator();
    }

    /** ASSERTION 3: a correct key verifies against its Argon2id hash. */
    public function testCorrectKeyVerifiesAgainstArgon2idHash(): void
    {
        $key  = 'doctorsecret';
        $hash = $this->auth->hash($key);

        $this->assertStringStartsWith('$argon2id$', $hash, 'Hash must use the Argon2id algorithm.');
        $this->assertTrue($this->auth->verify($key, $hash));
    }

    /** A wrong key must not verify. */
    public function testWrongKeyFailsVerification(): void
    {
        $hash = $this->auth->hash('doctorsecret');
        $this->assertFalse($this->auth->verify('wrongkey', $hash));
    }

    /** Bound check counts CHARACTERS: a 256-char multi-byte string is within bound. */
    public function testMultibyteBoundIsCharacterBased(): void
    {
        // 256 multi-byte characters = 512+ bytes. A byte check (strlen) would
        // wrongly reject this valid-length key; mb_strlen accepts it.
        $key256Chars = str_repeat('é', 256);

        $this->assertSame(256, mb_strlen($key256Chars, 'UTF-8'));
        $this->assertGreaterThan(256, strlen($key256Chars)); // proves byte != char
        $this->assertTrue($this->auth->isWithinBounds($key256Chars));
    }

    /** A 257-character key exceeds the semantic bound and is rejected. */
    public function testOverlongKeyIsRejected(): void
    {
        $this->assertFalse($this->auth->isWithinBounds(str_repeat('a', 257)));
    }
}
