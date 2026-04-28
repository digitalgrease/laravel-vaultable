<?php

namespace DigitalGrease\Vaultable\Actions\Fortify;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Services\RecoveryKeyService;
use DigitalGrease\Vaultable\Traits\HasVault;
use Illuminate\Http\Request;

class UnlockVaultOnLogin
{
    public function __construct(
        protected VaultServiceInterface $vaultService,
        protected RecoveryKeyService $recoveryKeyService,
        protected bool $recoveryEnabled,
    ) {}

    /**
     * Handle the incoming request after authentication.
     */
    public function handle(Request $request, callable $next): mixed
    {
        $response = $next($request);

        $user = $request->user();

        if (! $user || ! $this->hasVaultTrait($user)) {
            return $response;
        }

        $password = $request->input('password');

        if (! $password) {
            return $response;
        }

        if ($user->hasVault()) {
            $this->vaultService->unlockVault($user, $password);
        } else {
            $vaultHeader = $this->vaultService->createVault($user, $password);

            if ($this->recoveryEnabled) {
                $vmk = $this->vaultService->getVmk();
                $this->recoveryKeyService->generateRecoveryKey($vaultHeader, $vmk);
            }
        }

        return $response;
    }

    /**
     * Check if the model uses the HasVault trait.
     */
    protected function hasVaultTrait(object $model): bool
    {
        return in_array(HasVault::class, class_uses_recursive($model));
    }
}
