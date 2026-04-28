<?php

namespace DigitalGrease\Vaultable\Exceptions;

class RecoveryKeyRequiredException extends VaultException
{
    public function __construct(string $message = 'A recovery key is required to reset the password and recover vault access.')
    {
        parent::__construct($message);
    }
}
