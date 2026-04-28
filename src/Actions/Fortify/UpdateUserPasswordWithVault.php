<?php

namespace DigitalGrease\Vaultable\Actions\Fortify;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Traits\HasVault;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Fortify\Contracts\UpdatesUserPasswords;

class UpdateUserPasswordWithVault implements UpdatesUserPasswords
{
    public function __construct(
        protected UpdatesUserPasswords $updatesUserPasswords,
        protected VaultServiceInterface $vaultService,
    ) {}

    /**
     * Update the given user's password.
     *
     * @param array<string, string> $input
     */
    public function update(Authenticatable $user, array $input): void
    {
        if ($this->hasVaultTrait($user) && $user->hasVault()) {
            $this->vaultService->rotateKek(
                $user,
                $input['current_password'],
                $input['password'],
            );
        }

        $this->updatesUserPasswords->update($user, $input);
    }

    /**
     * Check if the model uses the HasVault trait.
     */
    protected function hasVaultTrait(object $model): bool
    {
        return in_array(HasVault::class, class_uses_recursive($model));
    }
}
