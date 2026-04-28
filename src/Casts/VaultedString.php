<?php

declare(strict_types=1);

namespace DigitalGrease\Vaultable\Casts;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Eloquent cast that transparently encrypts/decrypts a string attribute with
 * the current request's unlocked VMK.
 *
 * Storage format matches VaultServiceInterface::encrypt() — base64(nonce || ciphertext).
 *
 * @implements CastsAttributes<string|null, string|null>
 */
class VaultedString implements CastsAttributes
{
    public function get(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        return app(VaultServiceInterface::class)->decrypt((string) $value);
    }

    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        return app(VaultServiceInterface::class)->encrypt((string) $value);
    }
}
