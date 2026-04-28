<?php

namespace DigitalGrease\Vaultable\Services;

use DigitalGrease\Vaultable\Crypto\AeadEncryption;
use DigitalGrease\Vaultable\Crypto\KeyDerivation;
use DigitalGrease\Vaultable\Enums\AeadAlgorithm;
use DigitalGrease\Vaultable\Enums\KdfAlgorithm;
use DigitalGrease\Vaultable\Events\VaultRecoveryKeyGenerated;
use DigitalGrease\Vaultable\Exceptions\VaultDecryptionFailedException;
use DigitalGrease\Vaultable\Models\VaultHeader;
use DigitalGrease\Vaultable\Models\VaultRecoveryKey;
use Illuminate\Database\Eloquent\Model;

class RecoveryKeyService
{
    protected const RECOVERY_KEY_LENGTH = 32;

    public function __construct(
        protected AeadEncryption $aeadEncryption,
        protected KeyDerivation $keyDerivation,
        protected int $opsLimit,
        protected int $memLimit,
    ) {}

    /**
     * Generate a recovery key for the given vault header.
     *
     * @param VaultHeader $vaultHeader The vault header to create a recovery key for
     * @param string $vmk The plaintext VMK
     * @return string The plaintext recovery key (formatted for display)
     */
    public function generateRecoveryKey(VaultHeader $vaultHeader, string $vmk): string
    {
        $recoveryKey = random_bytes(self::RECOVERY_KEY_LENGTH);
        $nonce = $this->aeadEncryption->generateNonce();

        $encryptedVmk = $this->aeadEncryption->encrypt($vmk, $recoveryKey, $nonce);

        $recoveryKeyHash = password_hash(
            $recoveryKey,
            PASSWORD_ARGON2ID,
            [
                'memory_cost' => 65536,
                'time_cost' => 4,
                'threads' => 1,
            ]
        );

        $vaultHeader->recoveryKey()->updateOrCreate(
            ['vault_header_id' => $vaultHeader->id],
            [
                'aead_nonce' => $nonce,
                'encrypted_vmk' => $encryptedVmk,
                'recovery_key_hash' => $recoveryKeyHash,
            ]
        );

        $formattedKey = $this->formatRecoveryKey($recoveryKey);

        event(new VaultRecoveryKeyGenerated($vaultHeader->vaultable, $formattedKey));

        return $formattedKey;
    }

    /**
     * Recover a vault using a recovery key and set a new password.
     *
     * @param Model $model The model whose vault to recover
     * @param string $recoveryKey The plaintext recovery key (formatted or raw)
     * @param string $newPassword The new password to set
     * @return bool True if recovery was successful
     */
    public function recoverWithKey(Model $model, string $recoveryKey, string $newPassword): bool
    {
        $vaultHeader = $model->vaultHeader;

        if (! $vaultHeader || ! $vaultHeader->recoveryKey) {
            return false;
        }

        $recoveryKeyBinary = $this->parseRecoveryKey($recoveryKey);

        if (! $this->verifyRecoveryKey($vaultHeader, $recoveryKeyBinary)) {
            return false;
        }

        try {
            $vmk = $this->aeadEncryption->decrypt(
                $vaultHeader->recoveryKey->encrypted_vmk,
                $recoveryKeyBinary,
                $vaultHeader->recoveryKey->aead_nonce,
            );
        } catch (VaultDecryptionFailedException) {
            return false;
        }

        $newSalt = $this->keyDerivation->generateSalt();
        $newNonce = $this->aeadEncryption->generateNonce();

        $newKek = $this->keyDerivation->deriveKey(
            $newPassword,
            $newSalt,
            $this->opsLimit,
            $this->memLimit,
        );

        $newEncryptedVmk = $this->aeadEncryption->encrypt($vmk, $newKek, $newNonce);

        sodium_memzero($newKek);
        sodium_memzero($recoveryKeyBinary);

        $vaultHeader->update([
            'kdf_algorithm' => KdfAlgorithm::ARGON2ID,
            'kdf_salt' => $newSalt,
            'kdf_ops_limit' => $this->opsLimit,
            'kdf_mem_limit' => $this->memLimit,
            'aead_algorithm' => AeadAlgorithm::XCHACHA20_POLY1305,
            'aead_nonce' => $newNonce,
            'encrypted_vmk' => $newEncryptedVmk,
        ]);

        return true;
    }

    /**
     * Verify a recovery key hash without decryption.
     */
    public function verifyRecoveryKey(VaultHeader $vaultHeader, string $recoveryKey): bool
    {
        if (! $vaultHeader->recoveryKey) {
            return false;
        }

        $binaryKey = strlen($recoveryKey) === self::RECOVERY_KEY_LENGTH
            ? $recoveryKey
            : $this->parseRecoveryKey($recoveryKey);

        return password_verify($binaryKey, $vaultHeader->recoveryKey->recovery_key_hash);
    }

    /**
     * Format a recovery key for display.
     * Converts binary key to base64 and formats as XXXX XXXX XXXX XXXX XXXX XXXX.
     */
    public function formatRecoveryKey(string $binaryKey): string
    {
        $base64 = rtrim(base64_encode($binaryKey), '=');

        return implode(' ', str_split($base64, 4));
    }

    /**
     * Parse a formatted recovery key back to binary.
     */
    public function parseRecoveryKey(string $formattedKey): string
    {
        $base64 = str_replace(' ', '', $formattedKey);

        $padding = 4 - (strlen($base64) % 4);
        if ($padding < 4) {
            $base64 .= str_repeat('=', $padding);
        }

        return base64_decode($base64);
    }

    /**
     * Delete the recovery key for a vault.
     */
    public function deleteRecoveryKey(VaultHeader $vaultHeader): bool
    {
        if (! $vaultHeader->recoveryKey) {
            return false;
        }

        return $vaultHeader->recoveryKey->delete();
    }
}
