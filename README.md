# Laravel Vaultable

Polymorphic, zero-knowledge key vaulting for Laravel models. Per-user master
keys are derived from passwords with Argon2id, the master key itself is
generated server-side and stored only in encrypted form, and authenticated
encryption (XChaCha20-Poly1305) protects everything at rest. Includes deep
Laravel Fortify integration so vaults are created, unlocked, rotated and locked
automatically by the auth lifecycle.

- [Why](#why)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Automatic vault management](#automatic-vault-management)
  - [Manual vault operations](#manual-vault-operations)
  - [Encrypting application data](#encrypting-application-data)
  - [Encrypted Eloquent attribute](#encrypted-eloquent-attribute)
  - [Protecting routes](#protecting-routes)
  - [Recovery keys](#recovery-keys)
  - [Two-factor authentication](#two-factor-authentication)
- [Events](#events)
- [Exceptions](#exceptions)
- [Database schema](#database-schema)
- [Security architecture](#security-architecture)
- [Troubleshooting](#troubleshooting)
- [Testing](#testing)
- [Versioning](#versioning)
- [License](#license)

## Why

Storing user secrets (API tokens, card details, journal entries, private notes)
in a Laravel app usually means picking between two bad options:

1. **One server-wide encryption key.** Every row is decryptable by anyone who
   can read the database *and* the `.env` file.
2. **Encrypt with the user's password.** You can't compute anything for the
   user when they're not signed in, and a password change becomes a full
   re-encryption nightmare.

Laravel Vaultable splits these concerns. Each user has a long random **Vault
Master Key (VMK)** that does the actual encryption work. The VMK is itself
encrypted by a **Key Encryption Key (KEK)** derived from the user's password.
A password change re-wraps the VMK; the underlying ciphertexts stay valid.

Result: the server never persists plaintext keys, password changes are cheap,
and a database-only compromise yields nothing useful.

## How it works

```
                    Password (typed by user)
                            │
                  Argon2id  │  + per-user salt + (optional) global pepper
                            ▼
                          KEK  ─────  encrypts ────► encrypted_vmk  (DB row)
                            │                              │
                            └──── decrypts ◄───────────────┘
                                       │
                                       ▼
                                      VMK  (only ever lives in memory / session)
                                       │
                                       │  used to encrypt application data
                                       ▼
                                  Ciphertext rows
```

1. **Registration.** A 32-byte VMK is generated. A KEK is derived from the
   password with Argon2id. The VMK is encrypted with the KEK and persisted as a
   `vault_headers` row. The plaintext VMK is placed in the session using the
   split-key scheme described below. The KEK is wiped from memory.
2. **Login.** The KEK is re-derived from the password, used to decrypt the VMK
   from the stored row, and the VMK is placed in the session.
3. **Password change.** The KEK is re-derived from the *old* password to
   recover the VMK, then the VMK is re-encrypted with a new KEK derived from
   the *new* password. Only the `vault_headers` row changes — application
   ciphertexts are untouched.
4. **Logout / session timeout.** The VMK is wiped from the session.

## Requirements

- PHP 8.2 or newer
- Laravel 11
- `ext-sodium`
- A **server-side session driver** (`file`, `database`, `redis`, `memcached`).
  The `cookie` driver is rejected at boot — see
  [Security architecture](#security-architecture) for why.

Optional:

- **Laravel Fortify** — only required for automatic auth-flow integration.
  Listed in `composer.json` as a `suggest` rather than a hard `require` so
  you can install the package without it. Without Fortify, set
  `vaultable.fortify.auto_integrate = false` and drive the vault yourself
  with the [manual API](#manual-vault-operations).

## Installation

### 1. Install the package

```bash
composer require digitalgrease/laravel-vaultable
```

### 2. Publish the config and migrations

```bash
php artisan vendor:publish --tag=vaultable-config
php artisan vendor:publish --tag=vaultable-migrations
php artisan migrate
```

### 3. Configure environment variables

Add the following to your `.env` (and `.env.example`):

```dotenv
# 32-byte hex pepper applied to passwords before key derivation.
# Treat this like an APP_KEY: rotating it invalidates all existing vaults.
VAULTABLE_PEPPER=

# Auto-lock the vault after this many seconds of inactivity (0 = never).
VAULTABLE_SESSION_TIMEOUT=900

# Generate a one-time recovery key at vault creation.
VAULTABLE_RECOVERY_ENABLED=false
```

Generate a fresh pepper:

```bash
php -r 'echo bin2hex(random_bytes(32)), PHP_EOL;'
```

> **⚠️ Pepper rotation invalidates every existing vault.** Treat
> `VAULTABLE_PEPPER` as a long-lived secret. Store it in your secrets manager,
> not in source control.

### 4. Add the `HasVault` trait to your authenticatable model

```php
<?php

namespace App\Models;

use DigitalGrease\Vaultable\Traits\HasVault;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use HasVault;

    // ...
}
```

This is the switch that turns Fortify integration on for a given model. Models
without the trait are ignored by every Fortify hook the package installs.

That's it. With Fortify wired up, the next time a user registers or logs in,
their vault row will appear in `vault_headers`.

## Configuration

`config/vaultable.php` is the source of truth. Every option below has a sane
default; you only need to touch this file if you want to deviate.

```php
return [
    // Pepper applied to passwords before KDF (see env table above).
    'pepper' => env('VAULTABLE_PEPPER'),

    // Argon2id parameters. Higher = more secure but slower.
    // SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE / MEMLIMIT_MODERATE is a sensible default
    // for interactive logins on a typical web host.
    'kdf' => [
        'ops_limit' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        'mem_limit' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
    ],

    // Auto-lock window in seconds. 0 disables timeout-based locking.
    'session' => [
        'timeout' => env('VAULTABLE_SESSION_TIMEOUT', 900),
    ],

    // Generate one-time recovery keys when vaults are created.
    'recovery' => [
        'enabled' => env('VAULTABLE_RECOVERY_ENABLED', false),
    ],

    // Set to false to skip all Fortify-related bindings.
    'fortify' => [
        'auto_integrate' => true,
    ],

    // Polymorphic morph map. Add additional vaultable types here.
    'models' => [
        'user' => config('auth.providers.users.model'),
    ],
];
```

### Tuning Argon2id

Three useful constants ship with libsodium:

| Constant                                     | Approx. cost          | When to pick it          |
|----------------------------------------------|-----------------------|--------------------------|
| `SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE`  | ~70 ms, 64 MB         | Phones / weak servers    |
| `SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE`     | ~700 ms, 256 MB       | **Default**, web servers |
| `SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE`    | ~3.5 s, 1 GB          | Highly sensitive vaults  |

When you raise these values, vaults that were created with the older numbers
are transparently re-keyed on the next successful unlock — see
[`VaultService::upgradeKdfParameters`](src/Services/VaultService.php).

## Usage

### Automatic vault management

With `vaultable.fortify.auto_integrate = true` (the default) and the `HasVault`
trait on your User model, the auth lifecycle handles everything:

| Event                        | Effect                                                                       |
|------------------------------|------------------------------------------------------------------------------|
| Registration                 | Vault created, VMK placed in session, optional recovery key generated        |
| Login (no 2FA)               | Vault unlocked, VMK placed in session                                        |
| Login (2FA enabled)          | Password is held encrypted in session during the challenge; vault unlocks after the second factor verifies |
| Login of a pre-existing user with no vault | Vault is created from the typed password (back-fill mode)      |
| Password change              | KEK rotated, VMK preserved, application ciphertexts untouched                |
| Password reset (no recovery) | Old vault deleted, new vault created — **application ciphertexts become unreadable** |
| Password reset (recovery)    | VMK recovered from the recovery key, new KEK wraps it                        |
| Logout                       | VMK cleared from session                                                     |

### Manual vault operations

Resolve `VaultServiceInterface` from the container:

```php
use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;

$vault = app(VaultServiceInterface::class);

// Create a vault for a model that uses HasVault
$header = $vault->createVault($user, $password);

// Unlock with the user's password — populates the session
$ok = $vault->unlockVault($user, $password);

// Is a vault currently unlocked for this session?
if ($vault->isUnlocked()) {
    $vmk = $vault->getVmk(); // 32 bytes of binary key material
}

// Lock the vault (logout-style)
$vault->lockVault();

// Re-wrap the VMK with a new password
$vault->rotateKek($user, $oldPassword, $newPassword);
```

Or use the `Vault` facade:

```php
use DigitalGrease\Vaultable\Facades\Vault;

Vault::createVault($user, $password);
Vault::unlockVault($user, $password);

if (Vault::isUnlocked()) {
    $vmk = Vault::getVmk();
}

Vault::lockVault();
Vault::rotateKek($user, $oldPassword, $newPassword);

$encoded   = Vault::encrypt('secret');
$plaintext = Vault::decrypt($encoded);
```

The two are equivalent — both resolve to the same singleton. Pick whichever
fits your codebase: facades for shorter call sites and easy mocking
(`Vault::shouldReceive(...)`), constructor injection of
`VaultServiceInterface` for explicit dependencies.

### Encrypting application data

`VaultService` ships two convenience methods for encrypting and decrypting
arbitrary strings with the unlocked VMK. The output is a single
base64-encoded blob (nonce inline) safe to store in a `VARCHAR` or `TEXT`
column.

```php
use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;

$vault = app(VaultServiceInterface::class);

$encoded = $vault->encrypt('super secret note');
// "base64( nonce(24) || ciphertext+tag )"

$plaintext = $vault->decrypt($encoded);
// "super secret note"
```

`encrypt()` throws `VaultLockedException` if no vault is unlocked. `decrypt()`
throws `VaultLockedException` for a locked vault and
`VaultDecryptionFailedException` for a malformed or tampered payload.

A fresh nonce is generated on every call to `encrypt()`, so the same
plaintext produces a different ciphertext every time.

If you'd rather work with the lower-level primitives directly (multiple
encryptions sharing one nonce-domain, additional authenticated data, etc.),
the same building blocks are available as `app(AeadEncryption::class)` —
see the [development guide](docs/DEVELOPMENT.md#aeadencryption).

### Encrypted Eloquent attribute

The `VaultedString` cast wraps the helpers above so a column can be
transparently vaulted:

```php
use DigitalGrease\Vaultable\Casts\VaultedString;

class JournalEntry extends Model
{
    protected function casts(): array
    {
        return [
            'body' => VaultedString::class,
        ];
    }
}
```

Reads and writes go through the cast automatically:

```php
$entry = JournalEntry::create([
    'user_id' => $user->id,
    'body'    => 'today I learned something private',
]);

// later, on the same authenticated session:
$entry->fresh()->body; // "today I learned something private"
```

Vaulted columns are only readable while the vault is unlocked. Background
jobs and queued listeners can't decrypt them unless you explicitly propagate
the VMK to them. That is by design.

### Protecting routes

```php
Route::middleware(['auth', 'vault.unlocked'])->group(function () {
    Route::get('/secrets', [SecretController::class, 'index']);
    Route::post('/secrets', [SecretController::class, 'store']);
});
```

For HTML requests the middleware redirects to `login` when the vault is locked.
For JSON requests it throws `VaultLockedException`, which you can map to a 423
response in your exception handler.

### Recovery keys

Set `VAULTABLE_RECOVERY_ENABLED=true` to generate a one-time recovery key when
each vault is created. The plaintext recovery key is dispatched as the
`VaultRecoveryKeyGenerated` event; the **only** plaintext copy lives in that
event.

```php
use DigitalGrease\Vaultable\Events\VaultRecoveryKeyGenerated;
use Illuminate\Support\Facades\Event;

Event::listen(VaultRecoveryKeyGenerated::class, function ($event) {
    // $event->model        — The user
    // $event->recoveryKey  — The plaintext recovery key, formatted as
    //                         "ABCD EFGH IJKL MNOP QRST UVWX". Show ONCE.
    session()->flash('vault_recovery_key', $event->recoveryKey);
});
```

Display the key once at registration. Tell the user clearly that this is the
only copy and there is no way to retrieve it later:

```blade
@if (session('vault_recovery_key'))
    <div class="alert alert-warning">
        <strong>Save your recovery key.</strong>
        <p>This key recovers your vault if you forget your password.
           Store it somewhere safe — it will not be shown again.</p>
        <code>{{ session('vault_recovery_key') }}</code>
    </div>
@endif
```

When recovery is enabled, password reset (Fortify's "forgot password" flow)
*requires* a recovery key. Without one, the package raises
`RecoveryKeyRequiredException` rather than silently destroying the user's vault
contents.

To recover manually:

```php
use DigitalGrease\Vaultable\Services\RecoveryKeyService;

$recovered = app(RecoveryKeyService::class)
    ->recoverWithKey($user, $recoveryKey, $newPassword);
```

Recovery keys can be regenerated at any time:

```php
$header = $user->vaultHeader;
$vmk    = app(VaultServiceInterface::class)->getVmk();
app(RecoveryKeyService::class)->generateRecoveryKey($header, $vmk);
```

### Two-factor authentication

If `Fortify::confirmsTwoFactorAuthentication()` is on, the package replaces the
default `RedirectIfTwoFactorAuthenticatable` action. The user's password is
encrypted with an ephemeral key (libsodium `secretbox`), held in the session
across the 2FA challenge, then decrypted and used to unlock the vault after the
challenge succeeds. The encrypted password is wiped from the session as soon as
it is consumed.

You only need to call `unlockVaultAfterTwoFactor()` if you've customised the
2FA controller; the default Fortify view + the package handle it
transparently.

```php
use DigitalGrease\Vaultable\Actions\Fortify\TwoFactorAuthWithVault;

// Inside a custom 2FA verification handler, after the second factor is confirmed:
app(TwoFactorAuthWithVault::class)->unlockVaultAfterTwoFactor($request);
```

## Events

| Event                        | Payload                                            | Fired                                          |
|------------------------------|----------------------------------------------------|------------------------------------------------|
| `VaultCreated`               | `Model $model`, `VaultHeader $vaultHeader`         | After a new vault is created                   |
| `VaultUnlocked`              | `Model $model`, `VaultHeader $vaultHeader`         | After a successful unlock                      |
| `VaultLocked`                | (none)                                             | When `lockVault()` runs (logout, timeout, manual) |
| `VaultRecoveryKeyGenerated`  | `Model $model`, `string $recoveryKey` (plaintext) | When a recovery key is generated; only chance to capture the plaintext |

## Exceptions

| Exception                        | When                                                                  |
|----------------------------------|-----------------------------------------------------------------------|
| `VaultException`                 | Base class. Catch this if you don't care which vault failure happened |
| `VaultLockedException`           | Thrown by `getVmk()` and `vault.unlocked` middleware on a locked vault |
| `VaultDecryptionFailedException` | Thrown when AEAD decryption fails (wrong KEK, corrupted ciphertext)   |
| `RecoveryKeyRequiredException`   | Thrown during password reset when recovery is enabled but the recovery key was missing or invalid |

## Database schema

### `vault_headers`

| Column           | Type        | Notes                                              |
|------------------|-------------|----------------------------------------------------|
| `id`             | bigint PK   |                                                    |
| `vaultable_type` | string      | Polymorphic morph map alias (e.g. `user`)          |
| `vaultable_id`   | bigint      | FK-style id of the owning model                    |
| `kdf_algorithm`  | tinyint     | Cast to `KdfAlgorithm` enum                        |
| `kdf_salt`       | binary(16)  | Random per-vault salt                              |
| `kdf_ops_limit`  | int         | Argon2id time cost stored at creation              |
| `kdf_mem_limit`  | bigint      | Argon2id memory cost stored at creation            |
| `aead_algorithm` | string      | Cast to `AeadAlgorithm` enum                       |
| `aead_nonce`     | binary(24)  | Nonce used to wrap the VMK                         |
| `encrypted_vmk`  | binary(48)  | VMK ciphertext + auth tag                          |
| `version`        | int         | Schema version, default `1`                        |
| `metadata`       | json (null) | Free-form metadata; package never reads it         |
| `timestamps`     |             |                                                    |

Unique index on `(vaultable_type, vaultable_id)` — one vault per model.

### `vault_recovery_keys`

| Column              | Type        | Notes                                              |
|---------------------|-------------|----------------------------------------------------|
| `id`                | bigint PK   |                                                    |
| `vault_header_id`   | bigint      | FK to `vault_headers`, cascades on delete          |
| `aead_nonce`        | binary(24)  | Nonce for the recovery-encrypted VMK               |
| `encrypted_vmk`     | binary(48)  | VMK ciphertext under the recovery key              |
| `recovery_key_hash` | string      | `password_hash` of the recovery key, for lookup    |
| `timestamps`        |             |                                                    |

The plaintext recovery key is **never** stored. Only its Argon2id hash is.

## Security architecture

### Cryptographic primitives

| Purpose             | Algorithm                  | Source            |
|---------------------|----------------------------|-------------------|
| Password → key      | Argon2id (memory-hard KDF) | libsodium pwhash  |
| Authenticated encryption | XChaCha20-Poly1305 (24-byte nonce) | libsodium AEAD |
| Pepper application  | HMAC-SHA256                | PHP `hash_hmac`   |
| Recovery key hash   | Argon2id via `password_hash` | PHP password API |
| 2FA password hold   | XSalsa20-Poly1305 (`secretbox`) | libsodium    |

### Split-key VMK storage

The unlocked VMK is stored in two pieces, neither of which is useful alone:

```
┌─────────────────────────────────────────────────────────┐
│                   SERVER SESSION                        │
│   encrypted_vmk = XChaCha20-Poly1305(vmk, session_key)  │
│   nonce         = random 24 bytes                       │
└─────────────────────────────────────────────────────────┘
                            +
┌─────────────────────────────────────────────────────────┐
│              HTTPONLY · SECURE · LAX COOKIE             │
│   session_key  = random 32 bytes                        │
└─────────────────────────────────────────────────────────┘
                            ↓
              Both required to reconstruct VMK
```

| Attacker capability                | Can they read the VMK? | Why                                  |
|------------------------------------|------------------------|--------------------------------------|
| Database dump                      | No                     | Sees only `encrypted_vmk` (KEK-wrapped) |
| Server session store dump          | No                     | Sees the inner ciphertext but no session key |
| Stolen browser cookie (XSS)        | No                     | Cookie is `HttpOnly`, JS can't read it |
| MITM on HTTP                       | No                     | Cookie is `Secure`, only sent over TLS |
| Session store dump **and** cookie  | Yes                    | This is the threshold this design is meant to raise |

### Why the cookie session driver is rejected

Laravel's `cookie` session driver places session data on the client. With it,
both halves of the split-key would live on the client, defeating the security
model entirely. The package throws a `RuntimeException` at boot if it sees
`SESSION_DRIVER=cookie`. `array` is also rejected (except in tests).

### Memory hygiene

Sensitive byte strings are zeroed with `sodium_memzero()` once they're no
longer needed:

- KEKs are wiped immediately after they encrypt or decrypt the VMK.
- Session keys are wiped after they wrap or unwrap the session-stored VMK.
- The 2FA password key is wiped after it decrypts the held password.

## Troubleshooting

**`RuntimeException: Laravel Vaultable requires a server-side session driver`**
Set `SESSION_DRIVER` to `file`, `database`, `redis`, or `memcached`.

**`VaultLockedException` after a fresh login.**
The session key cookie is `Secure`, so it requires HTTPS. Local development
without TLS will *not* receive the cookie. Use `php artisan serve` with
HTTPS, Valet/Herd's HTTPS, or set up a tunnel.

**Existing users get no vault even after the upgrade.**
`UnlockVaultOnLogin` back-fills a vault on first login post-upgrade, using the
password the user just typed. Existing users have no vault until they log in
once after the trait is added.

**Password reset destroyed my user's data.**
Without recovery keys enabled, password reset *must* discard the old vault
because the password was the only path to the VMK. Enable
`VAULTABLE_RECOVERY_ENABLED=true` going forward.

**Unable to decrypt vaulted data in a queued job.**
The vault lives in the user's session; queued workers don't have one. Either
do the encrypt/decrypt at the request boundary, or design jobs to take a
short-lived re-derived KEK / hand-off token. The package intentionally does
not provide a "background decrypt" path.

## Testing

```bash
composer test
```

Tests run on Orchestra Testbench against an in-memory SQLite database. The
test suite covers crypto primitives, the service-provider wiring, the trait,
the recovery flow, and the end-to-end vault lifecycle.

When testing applications that use the package, the `array` session driver is
permitted under `runningUnitTests()`; everything else still goes through the
normal session.

## Versioning

Semantic versioning. Note:

- The `kdf_algorithm` and `aead_algorithm` enums are part of the on-disk
  format. Renaming or removing a case is a breaking change.
- Raising the default `kdf` ops/mem limits is a non-breaking change because
  existing vaults are transparently re-keyed on next unlock.
- Rotating `VAULTABLE_PEPPER` is **always** breaking — every vault is
  invalidated.

## License

MIT. See [LICENSE](LICENSE).
