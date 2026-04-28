<?php

namespace DigitalGrease\Vaultable\Contracts;

use DigitalGrease\Vaultable\Models\VaultHeader;
use Illuminate\Database\Eloquent\Model;

interface VaultServiceInterface
{
    /**
     * Create a new vault for the given model.
     *
     * @param Model $model The model to create a vault for
     * @param string $password The password to derive the KEK from
     * @return VaultHeader The created vault header
     */
    public function createVault(Model $model, string $password): VaultHeader;

    /**
     * Unlock a vault using the given password.
     *
     * @param Model $model The model whose vault to unlock
     * @param string $password The password to derive the KEK from
     * @return bool True if the vault was successfully unlocked
     */
    public function unlockVault(Model $model, string $password): bool;

    /**
     * Lock the currently unlocked vault (clear VMK from session).
     */
    public function lockVault(): void;

    /**
     * Check if a vault is currently unlocked.
     */
    public function isUnlocked(): bool;

    /**
     * Get the current VMK from session.
     *
     * @return string|null The VMK or null if not unlocked
     */
    public function getVmk(): ?string;

    /**
     * Rotate the KEK (re-encrypt VMK with a new password).
     *
     * @param Model $model The model whose vault to rotate
     * @param string $oldPassword The current password
     * @param string $newPassword The new password
     * @return bool True if rotation was successful
     */
    public function rotateKek(Model $model, string $oldPassword, string $newPassword): bool;

    /**
     * Encrypt application data with the unlocked VMK.
     *
     * Output format is base64(nonce || ciphertext) — a single string safe to
     * store in a VARCHAR/TEXT column. The nonce is regenerated on every call.
     *
     * @throws \DigitalGrease\Vaultable\Exceptions\VaultLockedException
     */
    public function encrypt(string $plaintext): string;

    /**
     * Decrypt application data with the unlocked VMK.
     *
     * Accepts the format produced by encrypt(): base64(nonce || ciphertext).
     *
     * @throws \DigitalGrease\Vaultable\Exceptions\VaultLockedException
     * @throws \DigitalGrease\Vaultable\Exceptions\VaultDecryptionFailedException
     */
    public function decrypt(string $encoded): string;
}
