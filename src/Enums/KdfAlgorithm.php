<?php

namespace DigitalGrease\Vaultable\Enums;

enum KdfAlgorithm: int
{
    case ARGON2ID = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13;
}
