<?php

namespace DigitalGrease\Vaultable\Models;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class VaultRecoveryKey extends Model
{
    protected $fillable = [
        'vault_header_id',
        'aead_nonce',
        'encrypted_vmk',
        'recovery_key_hash',
    ];

    /**
     * Get the vault header that this recovery key belongs to.
     */
    public function vaultHeader(): BelongsTo
    {
        return $this->belongsTo(VaultHeader::class);
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
