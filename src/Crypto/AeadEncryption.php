<?php

namespace DigitalGrease\Vaultable\Crypto;

use DigitalGrease\Vaultable\Exceptions\VaultDecryptionFailedException;
use SodiumException;

class AeadEncryption
{
    /**
     * The length of the nonce in bytes.
     */
    public const NONCE_LENGTH = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

    /**
     * The length of the key in bytes.
     */
    public const KEY_LENGTH = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

    /**
     * The length of the authentication tag in bytes.
     */
    public const TAG_LENGTH = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;

    /**
     * Generate a random nonce for encryption.
     *
     * @throws SodiumException
     */
    public function generateNonce(): string
    {
        return random_bytes(self::NONCE_LENGTH);
    }

    /**
     * Generate a random key (for VMK generation).
     *
     * @throws SodiumException
     */
    public function generateKey(): string
    {
        return random_bytes(self::KEY_LENGTH);
    }

    /**
     * Encrypt plaintext using XChaCha20-Poly1305.
     *
     * @param string $plaintext The data to encrypt
     * @param string $key The encryption key (32 bytes)
     * @param string $nonce The nonce (24 bytes)
     * @param string $additionalData Optional additional authenticated data
     * @return string The ciphertext with authentication tag
     *
     * @throws SodiumException
     */
    public function encrypt(
        string $plaintext,
        string $key,
        string $nonce,
        string $additionalData = '',
    ): string {
        return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $additionalData,
            $nonce,
            $key,
        );
    }

    /**
     * Decrypt ciphertext using XChaCha20-Poly1305.
     *
     * @param string $ciphertext The encrypted data with authentication tag
     * @param string $key The encryption key (32 bytes)
     * @param string $nonce The nonce (24 bytes)
     * @param string $additionalData Optional additional authenticated data
     * @return string The decrypted plaintext
     *
     * @throws VaultDecryptionFailedException If decryption fails
     * @throws SodiumException
     */
    public function decrypt(
        string $ciphertext,
        string $key,
        string $nonce,
        string $additionalData = '',
    ): string {
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            $additionalData,
            $nonce,
            $key,
        );

        if ($plaintext === false) {
            throw new VaultDecryptionFailedException(
                'Failed to decrypt vault: authentication tag mismatch or corrupted data.'
            );
        }

        return $plaintext;
    }
}
