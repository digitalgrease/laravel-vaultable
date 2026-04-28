<?php

namespace DigitalGrease\Vaultable\Services;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Crypto\AeadEncryption;
use DigitalGrease\Vaultable\Crypto\KeyDerivation;
use DigitalGrease\Vaultable\Enums\AeadAlgorithm;
use DigitalGrease\Vaultable\Enums\KdfAlgorithm;
use DigitalGrease\Vaultable\Events\VaultCreated;
use DigitalGrease\Vaultable\Events\VaultLocked;
use DigitalGrease\Vaultable\Events\VaultUnlocked;
use DigitalGrease\Vaultable\Exceptions\VaultDecryptionFailedException;
use DigitalGrease\Vaultable\Exceptions\VaultLockedException;
use DigitalGrease\Vaultable\Models\VaultHeader;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieJar;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

class VaultService implements VaultServiceInterface
{
    /**
     * Session key for the encrypted VMK.
     */
    protected const SESSION_ENCRYPTED_VMK_KEY = 'vaultable.encrypted_vmk';

    /**
     * Session key for the nonce used to encrypt the VMK.
     */
    protected const SESSION_VMK_NONCE_KEY = 'vaultable.vmk_nonce';

    /**
     * Session key for the unlock timestamp.
     */
    protected const SESSION_UNLOCK_TIME_KEY = 'vaultable.unlock_time';

    /**
     * Cookie name for the session key (used to decrypt VMK from session).
     */
    protected const COOKIE_SESSION_KEY = 'vaultable_session_key';

    public function __construct(
        protected KeyDerivation $keyDerivation,
        protected AeadEncryption $aeadEncryption,
        protected Session $session,
        protected CookieJar $cookie,
        protected Request $request,
        protected int $sessionTimeout,
        protected int $opsLimit,
        protected int $memLimit,
    ) {}

    /**
     * Create a new vault for the given model.
     */
    public function createVault(Model $model, string $password): VaultHeader
    {
        $vmk = $this->aeadEncryption->generateKey();
        $salt = $this->keyDerivation->generateSalt();
        $nonce = $this->aeadEncryption->generateNonce();

        $kek = $this->keyDerivation->deriveKey(
            $password,
            $salt,
            $this->opsLimit,
            $this->memLimit,
        );

        $encryptedVmk = $this->aeadEncryption->encrypt($vmk, $kek, $nonce);

        sodium_memzero($kek);

        $vaultHeader = $model->vaultHeader()->create([
            'kdf_algorithm' => KdfAlgorithm::ARGON2ID,
            'kdf_salt' => $salt,
            'kdf_ops_limit' => $this->opsLimit,
            'kdf_mem_limit' => $this->memLimit,
            'aead_algorithm' => AeadAlgorithm::XCHACHA20_POLY1305,
            'aead_nonce' => $nonce,
            'encrypted_vmk' => $encryptedVmk,
            'version' => 1,
        ]);

        $this->storeVmkInSession($vmk);

        event(new VaultCreated($model, $vaultHeader));

        return $vaultHeader;
    }

    /**
     * Unlock a vault using the given password.
     */
    public function unlockVault(Model $model, string $password): bool
    {
        $vaultHeader = $model->vaultHeader;

        if (! $vaultHeader) {
            return false;
        }

        $kek = $this->keyDerivation->deriveKey(
            $password,
            $vaultHeader->kdf_salt,
            $vaultHeader->kdf_ops_limit,
            $vaultHeader->kdf_mem_limit,
        );

        try {
            $vmk = $this->aeadEncryption->decrypt(
                $vaultHeader->encrypted_vmk,
                $kek,
                $vaultHeader->aead_nonce,
            );
        } catch (VaultDecryptionFailedException) {
            sodium_memzero($kek);

            return false;
        }

        sodium_memzero($kek);

        $this->storeVmkInSession($vmk);

        if ($this->keyDerivation->needsRehash(
            $vaultHeader->kdf_ops_limit,
            $vaultHeader->kdf_mem_limit,
            $this->opsLimit,
            $this->memLimit,
        )) {
            $this->upgradeKdfParameters($vaultHeader, $vmk, $password);
        }

        event(new VaultUnlocked($model, $vaultHeader));

        return true;
    }

    /**
     * Lock the currently unlocked vault.
     */
    public function lockVault(): void
    {
        $this->session->forget([
            self::SESSION_ENCRYPTED_VMK_KEY,
            self::SESSION_VMK_NONCE_KEY,
            self::SESSION_UNLOCK_TIME_KEY,
        ]);

        $this->cookie->queue(
            $this->cookie->forget(self::COOKIE_SESSION_KEY)
        );

        event(new VaultLocked);
    }

    /**
     * Check if a vault is currently unlocked.
     */
    public function isUnlocked(): bool
    {
        $encryptedVmk = $this->session->get(self::SESSION_ENCRYPTED_VMK_KEY);
        $nonce = $this->session->get(self::SESSION_VMK_NONCE_KEY);
        $unlockTime = $this->session->get(self::SESSION_UNLOCK_TIME_KEY);
        $sessionKey = $this->getSessionKeyFromCookie();

        if ($encryptedVmk === null || $nonce === null || $unlockTime === null || $sessionKey === null) {
            return false;
        }

        if ($this->sessionTimeout > 0 && (time() - $unlockTime) > $this->sessionTimeout) {
            $this->lockVault();

            return false;
        }

        return true;
    }

    /**
     * Get the current VMK from session.
     *
     * @throws VaultLockedException
     */
    public function getVmk(): ?string
    {
        if (! $this->isUnlocked()) {
            throw new VaultLockedException;
        }

        $this->session->put(self::SESSION_UNLOCK_TIME_KEY, time());

        return $this->decryptVmkFromSession();
    }

    /**
     * Rotate the KEK (re-encrypt VMK with a new password).
     */
    public function rotateKek(Model $model, string $oldPassword, string $newPassword): bool
    {
        $vaultHeader = $model->vaultHeader;

        if (! $vaultHeader) {
            return false;
        }

        $oldKek = $this->keyDerivation->deriveKey(
            $oldPassword,
            $vaultHeader->kdf_salt,
            $vaultHeader->kdf_ops_limit,
            $vaultHeader->kdf_mem_limit,
        );

        try {
            $vmk = $this->aeadEncryption->decrypt(
                $vaultHeader->encrypted_vmk,
                $oldKek,
                $vaultHeader->aead_nonce,
            );
        } catch (VaultDecryptionFailedException) {
            sodium_memzero($oldKek);

            return false;
        }

        sodium_memzero($oldKek);

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

        $vaultHeader->update([
            'kdf_salt' => $newSalt,
            'kdf_ops_limit' => $this->opsLimit,
            'kdf_mem_limit' => $this->memLimit,
            'aead_nonce' => $newNonce,
            'encrypted_vmk' => $newEncryptedVmk,
        ]);

        $this->storeVmkInSession($vmk);

        return true;
    }

    /**
     * Store the VMK in the session using split-key encryption.
     *
     * The VMK is encrypted with a random session key and stored in the server session.
     * The session key is stored in an HttpOnly secure cookie.
     * Both are required to reconstruct the VMK, providing defense-in-depth.
     */
    protected function storeVmkInSession(string $vmk): void
    {
        $sessionKey = $this->aeadEncryption->generateKey();
        $nonce = $this->aeadEncryption->generateNonce();

        $encryptedVmk = $this->aeadEncryption->encrypt($vmk, $sessionKey, $nonce);

        $this->session->put(self::SESSION_ENCRYPTED_VMK_KEY, base64_encode($encryptedVmk));
        $this->session->put(self::SESSION_VMK_NONCE_KEY, base64_encode($nonce));
        $this->session->put(self::SESSION_UNLOCK_TIME_KEY, time());

        $this->cookie->queue(
            $this->cookie->make(
                name: self::COOKIE_SESSION_KEY,
                value: base64_encode($sessionKey),
                minutes: $this->sessionTimeout > 0 ? (int) ceil($this->sessionTimeout / 60) : 0,
                path: '/',
                domain: null,
                secure: true,
                httpOnly: true,
                raw: false,
                sameSite: 'Lax',
            )
        );

        sodium_memzero($sessionKey);
    }

    /**
     * Decrypt the VMK from session using the session key from cookie.
     */
    protected function decryptVmkFromSession(): ?string
    {
        $sessionKey = $this->getSessionKeyFromCookie();
        $encryptedVmk = $this->session->get(self::SESSION_ENCRYPTED_VMK_KEY);
        $nonce = $this->session->get(self::SESSION_VMK_NONCE_KEY);

        if ($sessionKey === null || $encryptedVmk === null || $nonce === null) {
            return null;
        }

        try {
            $vmk = $this->aeadEncryption->decrypt(
                base64_decode($encryptedVmk),
                $sessionKey,
                base64_decode($nonce),
            );

            sodium_memzero($sessionKey);

            return $vmk;
        } catch (VaultDecryptionFailedException) {
            sodium_memzero($sessionKey);

            return null;
        }
    }

    /**
     * Get the session key from the cookie or queued cookies.
     *
     * Checks both the incoming request cookies and queued cookies (for same-request access).
     */
    protected function getSessionKeyFromCookie(): ?string
    {
        $cookieValue = $this->request->cookie(self::COOKIE_SESSION_KEY);

        if ($cookieValue === null) {
            $cookieValue = $this->getQueuedCookieValue(self::COOKIE_SESSION_KEY);
        }

        if ($cookieValue === null) {
            return null;
        }

        return base64_decode($cookieValue);
    }

    /**
     * Get a value from the queued cookies (for same-request access).
     */
    protected function getQueuedCookieValue(string $name): ?string
    {
        foreach ($this->cookie->getQueuedCookies() as $cookie) {
            if ($cookie->getName() === $name) {
                return $cookie->getValue();
            }
        }

        return null;
    }

    /**
     * Upgrade the KDF parameters to current settings.
     */
    protected function upgradeKdfParameters(VaultHeader $vaultHeader, string $vmk, string $password): void
    {
        $newSalt = $this->keyDerivation->generateSalt();
        $newNonce = $this->aeadEncryption->generateNonce();

        $newKek = $this->keyDerivation->deriveKey(
            $password,
            $newSalt,
            $this->opsLimit,
            $this->memLimit,
        );

        $newEncryptedVmk = $this->aeadEncryption->encrypt($vmk, $newKek, $newNonce);

        sodium_memzero($newKek);

        $vaultHeader->update([
            'kdf_salt' => $newSalt,
            'kdf_ops_limit' => $this->opsLimit,
            'kdf_mem_limit' => $this->memLimit,
            'aead_nonce' => $newNonce,
            'encrypted_vmk' => $newEncryptedVmk,
        ]);
    }
}
