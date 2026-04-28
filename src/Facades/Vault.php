<?php

declare(strict_types=1);

namespace DigitalGrease\Vaultable\Facades;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use Illuminate\Support\Facades\Facade;

/**
 * @method static \DigitalGrease\Vaultable\Models\VaultHeader createVault(\Illuminate\Database\Eloquent\Model $model, string $password)
 * @method static bool unlockVault(\Illuminate\Database\Eloquent\Model $model, string $password)
 * @method static void lockVault()
 * @method static bool isUnlocked()
 * @method static string|null getVmk()
 * @method static bool rotateKek(\Illuminate\Database\Eloquent\Model $model, string $oldPassword, string $newPassword)
 * @method static string encrypt(string $plaintext)
 * @method static string decrypt(string $encoded)
 *
 * @see \DigitalGrease\Vaultable\Contracts\VaultServiceInterface
 */
class Vault extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return VaultServiceInterface::class;
    }
}
