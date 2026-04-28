<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Pepper
    |--------------------------------------------------------------------------
    |
    | The pepper is a secret value that is combined with passwords before
    | deriving the KEK. Unlike salts (which are stored), peppers should be
    | kept in environment variables or a secret management system.
    |
    */

    'pepper' => env('VAULTABLE_PEPPER'),

    /*
    |--------------------------------------------------------------------------
    | Key Derivation Function (KDF) Settings
    |--------------------------------------------------------------------------
    |
    | These settings control the Argon2id parameters used for deriving
    | the Key Encryption Key (KEK) from user passwords. Higher values
    | increase security but also increase computation time.
    |
    | Note: The algorithm is fixed to Argon2id and cannot be changed.
    | Changing the algorithm would break existing vaults.
    |
    */

    'kdf' => [
        'ops_limit' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        'mem_limit' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
    ],

    /*
    |--------------------------------------------------------------------------
    | Session Settings
    |--------------------------------------------------------------------------
    |
    | These settings control how the decrypted VMK is stored in the session.
    | The timeout specifies how long (in seconds) before the vault is
    | automatically locked due to inactivity. Set to 0 to disable timeout.
    |
    */

    'session' => [
        'timeout' => env('VAULTABLE_SESSION_TIMEOUT', 900),
    ],

    /*
    |--------------------------------------------------------------------------
    | Recovery Key Settings
    |--------------------------------------------------------------------------
    |
    | When enabled, a recovery key is generated during vault creation that
    | allows users to recover their vault if they forget their password.
    | The recovery key should be stored securely by the user.
    |
    */

    'recovery' => [
        'enabled' => env('VAULTABLE_RECOVERY_ENABLED', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Fortify Integration
    |--------------------------------------------------------------------------
    |
    | When enabled, the package will automatically integrate with Laravel
    | Fortify to handle vault creation during registration, unlocking
    | during login, and KEK rotation during password changes.
    |
    */

    'fortify' => [
        'auto_integrate' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Models
    |--------------------------------------------------------------------------
    |
    | The models configuration allows you to specify which models use the
    | vault system. This is primarily used for the morphMap registration
    | to ensure polymorphic relationships work correctly.
    |
    */

    'models' => [
        'user' => config('auth.providers.users.model'),
    ],
];
