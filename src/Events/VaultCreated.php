<?php

namespace DigitalGrease\Vaultable\Events;

use DigitalGrease\Vaultable\Models\VaultHeader;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class VaultCreated
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public Model $model,
        public VaultHeader $vaultHeader,
    ) {}
}
