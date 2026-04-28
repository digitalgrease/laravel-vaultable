<?php

namespace DigitalGrease\Vaultable\Exceptions;

class VaultLockedException extends VaultException
{
    public function __construct(string $message = 'Vault is locked. Please authenticate to unlock.')
    {
        parent::__construct($message);
    }
}
