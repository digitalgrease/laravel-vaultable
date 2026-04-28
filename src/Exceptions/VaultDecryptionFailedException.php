<?php

namespace DigitalGrease\Vaultable\Exceptions;

class VaultDecryptionFailedException extends VaultException
{
    public function __construct(string $message = 'Failed to decrypt vault. The password may be incorrect.')
    {
        parent::__construct($message);
    }
}
