<?php

namespace DigitalGrease\Vaultable\Tests\Unit\Crypto;

use DigitalGrease\Vaultable\Crypto\AeadEncryption;
use DigitalGrease\Vaultable\Exceptions\VaultDecryptionFailedException;
use DigitalGrease\Vaultable\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class AeadEncryptionTest extends TestCase
{
    #[Test]
    public function it_generates_nonce_of_correct_length(): void
    {
        $encryption = new AeadEncryption;

        $nonce = $encryption->generateNonce();

        $this->assertSame(AeadEncryption::NONCE_LENGTH, strlen($nonce));
    }

    #[Test]
    public function it_generates_key_of_correct_length(): void
    {
        $encryption = new AeadEncryption;

        $key = $encryption->generateKey();

        $this->assertSame(AeadEncryption::KEY_LENGTH, strlen($key));
    }

    #[Test]
    public function it_encrypts_and_decrypts_data(): void
    {
        $encryption = new AeadEncryption;
        $key = $encryption->generateKey();
        $nonce = $encryption->generateNonce();
        $plaintext = 'Hello, World!';

        $ciphertext = $encryption->encrypt($plaintext, $key, $nonce);
        $decrypted = $encryption->decrypt($ciphertext, $key, $nonce);

        $this->assertSame($plaintext, $decrypted);
    }

    #[Test]
    public function it_produces_ciphertext_with_authentication_tag(): void
    {
        $encryption = new AeadEncryption;
        $key = $encryption->generateKey();
        $nonce = $encryption->generateNonce();
        $plaintext = 'Hello, World!';

        $ciphertext = $encryption->encrypt($plaintext, $key, $nonce);

        $this->assertSame(
            strlen($plaintext) + AeadEncryption::TAG_LENGTH,
            strlen($ciphertext)
        );
    }

    #[Test]
    public function it_fails_decryption_with_wrong_key(): void
    {
        $encryption = new AeadEncryption;
        $key = $encryption->generateKey();
        $wrongKey = $encryption->generateKey();
        $nonce = $encryption->generateNonce();
        $plaintext = 'Hello, World!';

        $ciphertext = $encryption->encrypt($plaintext, $key, $nonce);

        $this->expectException(VaultDecryptionFailedException::class);
        $encryption->decrypt($ciphertext, $wrongKey, $nonce);
    }

    #[Test]
    public function it_fails_decryption_with_wrong_nonce(): void
    {
        $encryption = new AeadEncryption;
        $key = $encryption->generateKey();
        $nonce = $encryption->generateNonce();
        $wrongNonce = $encryption->generateNonce();
        $plaintext = 'Hello, World!';

        $ciphertext = $encryption->encrypt($plaintext, $key, $nonce);

        $this->expectException(VaultDecryptionFailedException::class);
        $encryption->decrypt($ciphertext, $key, $wrongNonce);
    }

    #[Test]
    public function it_fails_decryption_with_tampered_ciphertext(): void
    {
        $encryption = new AeadEncryption;
        $key = $encryption->generateKey();
        $nonce = $encryption->generateNonce();
        $plaintext = 'Hello, World!';

        $ciphertext = $encryption->encrypt($plaintext, $key, $nonce);
        $tamperedCiphertext = $ciphertext;
        $tamperedCiphertext[0] = chr(ord($tamperedCiphertext[0]) ^ 1);

        $this->expectException(VaultDecryptionFailedException::class);
        $encryption->decrypt($tamperedCiphertext, $key, $nonce);
    }

    #[Test]
    public function it_encrypts_with_additional_authenticated_data(): void
    {
        $encryption = new AeadEncryption;
        $key = $encryption->generateKey();
        $nonce = $encryption->generateNonce();
        $plaintext = 'Hello, World!';
        $aad = 'additional-data';

        $ciphertext = $encryption->encrypt($plaintext, $key, $nonce, $aad);
        $decrypted = $encryption->decrypt($ciphertext, $key, $nonce, $aad);

        $this->assertSame($plaintext, $decrypted);
    }

    #[Test]
    public function it_fails_decryption_with_wrong_additional_data(): void
    {
        $encryption = new AeadEncryption;
        $key = $encryption->generateKey();
        $nonce = $encryption->generateNonce();
        $plaintext = 'Hello, World!';
        $aad = 'additional-data';

        $ciphertext = $encryption->encrypt($plaintext, $key, $nonce, $aad);

        $this->expectException(VaultDecryptionFailedException::class);
        $encryption->decrypt($ciphertext, $key, $nonce, 'wrong-additional-data');
    }
}
