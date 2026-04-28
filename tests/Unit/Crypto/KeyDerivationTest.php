<?php

namespace DigitalGrease\Vaultable\Tests\Unit\Crypto;

use DigitalGrease\Vaultable\Crypto\KeyDerivation;
use DigitalGrease\Vaultable\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class KeyDerivationTest extends TestCase
{
    #[Test]
    public function it_generates_salt_of_correct_length(): void
    {
        $keyDerivation = new KeyDerivation;

        $salt = $keyDerivation->generateSalt();

        $this->assertSame(KeyDerivation::SALT_LENGTH, strlen($salt));
    }

    #[Test]
    public function it_derives_key_of_correct_length(): void
    {
        $keyDerivation = new KeyDerivation;
        $salt = $keyDerivation->generateSalt();

        $key = $keyDerivation->deriveKey(
            'password123',
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );

        $this->assertSame(KeyDerivation::KEY_LENGTH, strlen($key));
    }

    #[Test]
    public function it_derives_same_key_with_same_inputs(): void
    {
        $keyDerivation = new KeyDerivation;
        $salt = $keyDerivation->generateSalt();

        $key1 = $keyDerivation->deriveKey(
            'password123',
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );

        $key2 = $keyDerivation->deriveKey(
            'password123',
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );

        $this->assertSame($key1, $key2);
    }

    #[Test]
    public function it_derives_different_keys_with_different_passwords(): void
    {
        $keyDerivation = new KeyDerivation;
        $salt = $keyDerivation->generateSalt();

        $key1 = $keyDerivation->deriveKey(
            'password123',
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );

        $key2 = $keyDerivation->deriveKey(
            'different-password',
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );

        $this->assertNotSame($key1, $key2);
    }

    #[Test]
    public function it_derives_different_keys_with_different_salts(): void
    {
        $keyDerivation = new KeyDerivation;

        $key1 = $keyDerivation->deriveKey(
            'password123',
            $keyDerivation->generateSalt(),
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );

        $key2 = $keyDerivation->deriveKey(
            'password123',
            $keyDerivation->generateSalt(),
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );

        $this->assertNotSame($key1, $key2);
    }

    #[Test]
    public function it_applies_pepper_to_password(): void
    {
        $keyDerivationWithPepper = new KeyDerivation('my-secret-pepper');
        $keyDerivationWithoutPepper = new KeyDerivation;
        $salt = $keyDerivationWithoutPepper->generateSalt();

        $keyWithPepper = $keyDerivationWithPepper->deriveKey(
            'password123',
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );

        $keyWithoutPepper = $keyDerivationWithoutPepper->deriveKey(
            'password123',
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );

        $this->assertNotSame($keyWithPepper, $keyWithoutPepper);
    }

    #[Test]
    public function it_detects_when_rehash_is_needed(): void
    {
        $keyDerivation = new KeyDerivation;

        $needsRehash = $keyDerivation->needsRehash(
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        );

        $this->assertTrue($needsRehash);
    }

    #[Test]
    public function it_detects_when_rehash_is_not_needed(): void
    {
        $keyDerivation = new KeyDerivation;

        $needsRehash = $keyDerivation->needsRehash(
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        );

        $this->assertFalse($needsRehash);
    }
}
