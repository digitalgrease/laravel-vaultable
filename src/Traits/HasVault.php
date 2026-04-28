<?php

namespace DigitalGrease\Vaultable\Traits;

use DigitalGrease\Vaultable\Models\VaultHeader;
use Illuminate\Database\Eloquent\Relations\MorphOne;

trait HasVault
{
    /**
     * Get the vault header for this model.
     */
    public function vaultHeader(): MorphOne
    {
        return $this->morphOne(VaultHeader::class, 'vaultable');
    }

    /**
     * Check if this model has a vault.
     */
    public function hasVault(): bool
    {
        return $this->vaultHeader()->exists();
    }
}
