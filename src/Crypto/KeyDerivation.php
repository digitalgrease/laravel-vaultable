<?php

namespace DigitalGrease\Vaultable\Crypto;

use DigitalGrease\Vaultable\Enums\KdfAlgorithm;
use SodiumException;

class KeyDerivation
{
    /**
     * The length of the derived key in bytes.
     */
    public const KEY_LENGTH = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

    /**
     * The length of the salt in bytes.
     */
    public const SALT_LENGTH = SODIUM_CRYPTO_PWHASH_SALTBYTES;

    public function __construct(
        protected ?string $pepper = null,
    ) {}

    /**
     * Generate a random salt for key derivation.
     *
     * @throws SodiumException
     */
    public function generateSalt(): string
    {
        return random_bytes(self::SALT_LENGTH);
    }

    /**
     * Derive a key encryption key (KEK) from a password using Argon2id.
     *
     * @param string $password The user's password
     * @param string $salt Random salt (16 bytes)
     * @param int $opsLimit The number of operations (time cost)
     * @param int $memLimit The memory limit in bytes
     * @return string The derived key (32 bytes)
     *
     * @throws SodiumException
     */
    public function deriveKey(
        string $password,
        string $salt,
        int $opsLimit,
        int $memLimit,
    ): string {
        $pepperedPassword = $this->applyPepper($password);

        return sodium_crypto_pwhash(
            self::KEY_LENGTH,
            $pepperedPassword,
            $salt,
            $opsLimit,
            $memLimit,
            KdfAlgorithm::ARGON2ID->value,
        );
    }

    /**
     * Check if the current KDF parameters differ from stored parameters.
     * Returns true if the vault should be re-keyed with updated parameters.
     */
    public function needsRehash(
        int $storedOpsLimit,
        int $storedMemLimit,
        int $currentOpsLimit,
        int $currentMemLimit,
    ): bool {
        return $storedOpsLimit !== $currentOpsLimit
            || $storedMemLimit !== $currentMemLimit;
    }

    /**
     * Apply pepper to the password using HMAC-SHA256.
     * If no pepper is configured, returns the password unchanged.
     */
    protected function applyPepper(string $password): string
    {
        if ($this->pepper === null || $this->pepper === '') {
            return $password;
        }

        return hash_hmac('sha256', $password, $this->pepper, binary: true);
    }
}
