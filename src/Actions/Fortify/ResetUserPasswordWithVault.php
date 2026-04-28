<?php

namespace DigitalGrease\Vaultable\Actions\Fortify;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Exceptions\RecoveryKeyRequiredException;
use DigitalGrease\Vaultable\Services\RecoveryKeyService;
use DigitalGrease\Vaultable\Traits\HasVault;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Fortify\Contracts\ResetsUserPasswords;

class ResetUserPasswordWithVault implements ResetsUserPasswords
{
    public function __construct(
        protected ResetsUserPasswords $resetsUserPasswords,
        protected VaultServiceInterface $vaultService,
        protected RecoveryKeyService $recoveryKeyService,
        protected bool $recoveryEnabled,
    ) {}

    /**
     * Reset the given user's password.
     *
     * @param array<string, string> $input
     *
     * @throws RecoveryKeyRequiredException
     */
    public function reset(Authenticatable $user, array $input): void
    {
        if ($this->hasVaultTrait($user) && $user->hasVault()) {
            $this->handleVaultRecovery($user, $input);
        }

        $this->resetsUserPasswords->reset($user, $input);
    }

    /**
     * Handle vault recovery during password reset.
     *
     * @param array<string, string> $input
     *
     * @throws RecoveryKeyRequiredException
     */
    protected function handleVaultRecovery(Authenticatable $user, array $input): void
    {
        $recoveryKey = $input['recovery_key'] ?? null;

        if ($this->recoveryEnabled && $user->vaultHeader?->recoveryKey) {
            if (! $recoveryKey) {
                throw new RecoveryKeyRequiredException;
            }

            $recovered = $this->recoveryKeyService->recoverWithKey(
                $user,
                $recoveryKey,
                $input['password'],
            );

            if (! $recovered) {
                throw new RecoveryKeyRequiredException('The recovery key is invalid.');
            }
        } else {
            $user->vaultHeader?->delete();

            $vaultHeader = $this->vaultService->createVault($user, $input['password']);

            if ($this->recoveryEnabled) {
                $vmk = $this->vaultService->getVmk();
                $this->recoveryKeyService->generateRecoveryKey($vaultHeader, $vmk);
            }
        }
    }

    /**
     * Check if the model uses the HasVault trait.
     */
    protected function hasVaultTrait(object $model): bool
    {
        return in_array(HasVault::class, class_uses_recursive($model));
    }
}
