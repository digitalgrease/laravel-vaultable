<?php

namespace DigitalGrease\Vaultable\Actions\Fortify;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Services\RecoveryKeyService;
use DigitalGrease\Vaultable\Traits\HasVault;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Laravel\Fortify\Actions\RedirectIfTwoFactorAuthenticatable as FortifyRedirectIfTwoFactorAuthenticatable;
use Laravel\Fortify\Fortify;
use Laravel\Fortify\TwoFactorAuthenticatable;

class TwoFactorAuthWithVault extends FortifyRedirectIfTwoFactorAuthenticatable
{
    protected const SESSION_ENCRYPTED_PASSWORD_KEY = 'vaultable.2fa_password';
    protected const SESSION_ENCRYPTION_KEY_KEY = 'vaultable.2fa_key';

    protected VaultServiceInterface $vaultService;

    protected RecoveryKeyService $recoveryKeyService;

    protected bool $recoveryEnabled;

    public function __construct(
        StatefulGuard $guard,
        VaultServiceInterface $vaultService,
        RecoveryKeyService $recoveryKeyService,
        bool $recoveryEnabled,
    ) {
        parent::__construct($guard);

        $this->vaultService = $vaultService;
        $this->recoveryKeyService = $recoveryKeyService;
        $this->recoveryEnabled = $recoveryEnabled;
    }

    /**
     * Handle the incoming request.
     */
    public function handle(Request $request, callable $next): mixed
    {
        $user = $this->validateCredentials($request);

        if (Fortify::confirmsTwoFactorAuthentication()) {
            if (optional($user)->two_factor_secret &&
                ! is_null(optional($user)->two_factor_confirmed_at) &&
                in_array(TwoFactorAuthenticatable::class, class_uses_recursive($user))) {
                $this->storePasswordForTwoFactor($request);

                return $this->twoFactorChallengeResponse($request, $user);
            }
        } else {
            if (optional($user)->two_factor_secret &&
                in_array(TwoFactorAuthenticatable::class, class_uses_recursive($user))) {
                $this->storePasswordForTwoFactor($request);

                return $this->twoFactorChallengeResponse($request, $user);
            }
        }

        return $next($request);
    }

    /**
     * Store the password encrypted in session for 2FA flow.
     */
    protected function storePasswordForTwoFactor(Request $request): void
    {
        $password = $request->input('password');

        $key = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $encrypted = sodium_crypto_secretbox($password, $nonce, $key);

        $request->session()->put(self::SESSION_ENCRYPTED_PASSWORD_KEY, base64_encode($nonce.$encrypted));
        $request->session()->put(self::SESSION_ENCRYPTION_KEY_KEY, base64_encode($key));
    }

    /**
     * Retrieve and decrypt the password stored during 2FA flow.
     */
    public static function retrievePasswordFromSession(Request $request): ?string
    {
        $encryptedData = $request->session()->get(self::SESSION_ENCRYPTED_PASSWORD_KEY);
        $keyData = $request->session()->get(self::SESSION_ENCRYPTION_KEY_KEY);

        if (! $encryptedData || ! $keyData) {
            return null;
        }

        $data = base64_decode($encryptedData);
        $key = base64_decode($keyData);

        $nonce = substr($data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($data, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $password = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);

        $request->session()->forget([self::SESSION_ENCRYPTED_PASSWORD_KEY, self::SESSION_ENCRYPTION_KEY_KEY]);

        sodium_memzero($key);

        return $password !== false ? $password : null;
    }

    /**
     * Unlock vault after successful 2FA verification.
     */
    public function unlockVaultAfterTwoFactor(Request $request): void
    {
        $user = $request->user();

        if (! $user || ! $this->hasVaultTrait($user)) {
            return;
        }

        $password = self::retrievePasswordFromSession($request);

        if (! $password) {
            return;
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

        sodium_memzero($password);
    }

    /**
     * Check if the model uses the HasVault trait.
     */
    protected function hasVaultTrait(object $model): bool
    {
        return in_array(HasVault::class, class_uses_recursive($model));
    }
}
