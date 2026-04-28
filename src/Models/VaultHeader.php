<?php

namespace DigitalGrease\Vaultable\Models;

use DigitalGrease\Vaultable\Enums\AeadAlgorithm;
use DigitalGrease\Vaultable\Enums\KdfAlgorithm;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Database\Eloquent\Relations\MorphTo;

class VaultHeader extends Model
{
    protected $fillable = [
        'vaultable_type',
        'vaultable_id',
        'kdf_algorithm',
        'kdf_salt',
        'kdf_ops_limit',
        'kdf_mem_limit',
        'aead_algorithm',
        'aead_nonce',
        'encrypted_vmk',
        'version',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'kdf_algorithm' => KdfAlgorithm::class,
            'kdf_ops_limit' => 'integer',
            'kdf_mem_limit' => 'integer',
            'aead_algorithm' => AeadAlgorithm::class,
            'version' => 'integer',
            'metadata' => 'array',
        ];
    }

    /**
     * Get the parent vaultable model.
     */
    public function vaultable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * Get the recovery key for this vault header.
     */
    public function recoveryKey(): HasOne
    {
        return $this->hasOne(VaultRecoveryKey::class);
    }

    /**
     * Get the KDF salt as binary.
     */
    protected function kdfSalt(): Attribute
    {
        return Attribute::make(
            get: fn (?string $value) => $value !== null ? base64_decode($value) : null,
            set: fn (?string $value) => $value !== null ? base64_encode($value) : null,
        );
    }

    /**
     * Get the AEAD nonce as binary.
     */
    protected function aeadNonce(): Attribute
    {
        return Attribute::make(
            get: fn (?string $value) => $value !== null ? base64_decode($value) : null,
            set: fn (?string $value) => $value !== null ? base64_encode($value) : null,
        );
    }

    /**
     * Get the encrypted VMK as binary.
     */
    protected function encryptedVmk(): Attribute
    {
        return Attribute::make(
            get: fn (?string $value) => $value !== null ? base64_decode($value) : null,
            set: fn (?string $value) => $value !== null ? base64_encode($value) : null,
        );
    }
}
