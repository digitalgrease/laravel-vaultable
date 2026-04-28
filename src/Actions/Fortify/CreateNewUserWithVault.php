<?php

namespace DigitalGrease\Vaultable\Actions\Fortify;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Services\RecoveryKeyService;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Fortify\Contracts\CreatesNewUsers;

class CreateNewUserWithVault implements CreatesNewUsers
{
    public function __construct(
        protected CreatesNewUsers $createNewUser,
        protected VaultServiceInterface $vaultService,
        protected RecoveryKeyService $recoveryKeyService,
        protected bool $recoveryEnabled,
    ) {}

    /**
     * Create a newly registered user and their vault.
     *
     * @param array<string, string> $input
     */
    public function create(array $input): Authenticatable
    {
        $user = $this->createNewUser->create($input);

        $password = $input['password'];

        $vaultHeader = $this->vaultService->createVault($user, $password);

        if ($this->recoveryEnabled) {
            $vmk = $this->vaultService->getVmk();
            $this->recoveryKeyService->generateRecoveryKey($vaultHeader, $vmk);
        }

        return $user;
    }
}
