<?php

namespace DigitalGrease\Vaultable\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class VaultRecoveryKeyGenerated
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public Model $model,
        public string $recoveryKey,
    ) {}
}
