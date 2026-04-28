# Development guide

This document is the long-form companion to the README. It exists to explain
**why** the package is shaped the way it is — what every file does, which
design choices are load-bearing, and where the seams are if you want to
extend it.

If you only want to *use* the package, the [README](../README.md) is enough.

- [Goals and non-goals](#goals-and-non-goals)
- [Architecture at a glance](#architecture-at-a-glance)
- [The cryptographic design](#the-cryptographic-design)
- [The split-key VMK in detail](#the-split-key-vmk-in-detail)
- [File-by-file tour](#file-by-file-tour)
- [Fortify integration deep-dive](#fortify-integration-deep-dive)
- [Two-factor authentication flow](#two-factor-authentication-flow)
- [KDF auto-upgrade](#kdf-auto-upgrade)
- [Recovery keys](#recovery-keys)
- [Sessions, cookies, and request boundaries](#sessions-cookies-and-request-boundaries)
- [Logout and locking](#logout-and-locking)
- [Testing strategy](#testing-strategy)
- [Extension points](#extension-points)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)

## Goals and non-goals

**Goals.**
- Per-user master keys, not a single server-wide key.
- The server never persists plaintext key material.
- Password changes don't require re-encrypting application data.
- Plays well with stock Laravel Fortify so a Jetstream/Breeze app can adopt
  it with one trait + one env var.
- Strong, modern primitives (Argon2id, XChaCha20-Poly1305) by default.

**Non-goals.**
- *Encrypted search.* The package gives you a key; it does not build searchable
  encryption schemes for you.
- *Background decryption.* Queued jobs don't have a session, so they can't
  decrypt vaulted data without an explicit hand-off mechanism — and the
  package doesn't ship one. This is by design.
- *Replacing app-level encryption.* If you only need a single server key,
  Laravel's built-in `Crypt` facade is fine. This package exists for the case
  where per-user key isolation actually matters.
- *Hiding metadata.* The fact that user X has secrets at all, the row count,
  timestamps, sizes — none of that is hidden. Only the contents are.

## Architecture at a glance

```
┌────────────────────────────────────────────────────────────────────────┐
│                            ServiceProvider                             │
│                                                                        │
│  register():                       boot():                             │
│   • Bind KeyDerivation             • Validate session driver           │
│   • Bind AeadEncryption            • Publish config + migrations       │
│   • Bind VaultService              • Register morph map                │
│   • Bind RecoveryKeyService        • Alias 'vault.unlocked' middleware │
│                                    • Listen to Auth Logout             │
│                                    • If Fortify exists: extend()       │
│                                       Fortify contracts and pipeline   │
└────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────┐ ┌─────────────────────────┐ ┌───────────────┐
│       Crypto layer       │ │     Service layer       │ │  HTTP layer   │
│                          │ │                         │ │               │
│  KeyDerivation (Argon2id)│ │  VaultService           │ │  EnsureVault  │
│  AeadEncryption          │ │  RecoveryKeyService     │ │  Unlocked     │
│  (XChaCha20-Poly1305)    │ │                         │ │               │
└──────────────────────────┘ └─────────────────────────┘ └───────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│                            Persistence                                 │
│                                                                        │
│  VaultHeader  (one per vaultable model)                                │
│  VaultRecoveryKey  (zero or one per VaultHeader)                       │
└────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  Fortify auth-flow integration                         │
│                                                                        │
│  CreateNewUserWithVault   ──decorates──►  CreatesNewUsers              │
│  UpdateUserPasswordWith…  ──decorates──►  UpdatesUserPasswords         │
│  ResetUserPasswordWith…   ──decorates──►  ResetsUserPasswords          │
│  TwoFactorAuthWithVault   ──replaces ──►  RedirectIfTwoFactorAuthent…  │
│  UnlockVaultOnLogin       ──appended ──►  Fortify auth pipeline tail   │
└────────────────────────────────────────────────────────────────────────┘
```

## The cryptographic design

### Three keys, one secret per user

| Layer  | Name             | Lifetime          | Where it lives                                                 |
|--------|------------------|-------------------|----------------------------------------------------------------|
| Input  | Password         | Until logout      | Never persisted; the user types it                             |
| Middle | KEK              | Microseconds      | Memory only, wiped immediately after use with `sodium_memzero` |
| Output | VMK              | Until session ends| Encrypted form in `vault_headers`; runtime form in session     |

The KEK exists just long enough to wrap or unwrap the VMK. Derivation is
expensive (intentionally — Argon2id at MODERATE cost is around 700 ms / 256 MB
on a typical web server). The VMK is cheap to use because it's a 32-byte
symmetric key.

### Why these primitives

**Argon2id over PBKDF2 / bcrypt / scrypt.** Argon2id is the
PHC-competition winner and the algorithm explicitly recommended for password
hashing in 2026. It is memory-hard (resists GPU/ASIC), has a tunable parallelism
parameter (we pin it), and is exposed by libsodium across all the platforms
PHP runs on.

**XChaCha20-Poly1305 over AES-GCM.** Both are AEADs. XChaCha20-Poly1305 has
a 24-byte (192-bit) nonce, which is wide enough that random nonces effectively
never collide. AES-GCM has a 12-byte nonce, which makes random-nonce schemes
borderline; you'd want a counter, which complicates everything. ChaCha20 is
also constant-time on hardware that lacks AES-NI, which matters across the
range of servers a Laravel app might run on.

**HMAC-SHA256 for pepper application.** The pepper is mixed into the password
before it reaches the KDF: `pre_kdf = HMAC_SHA256(pepper, password)`. This way,
the password's actual bytes never reach `sodium_crypto_pwhash` — only their
HMAC does. An attacker who exfiltrates the database but not the pepper learns
nothing; an attacker who exfiltrates the pepper but not the database can still
only run an offline dictionary attack against Argon2id, which is
prohibitively expensive.

**`secretbox` (XSalsa20-Poly1305) for the 2FA password hand-off.** This is a
simpler API than the AEAD variant and we don't need additional authenticated
data here — the password is the only payload.

### Why the recovery key path uses `password_hash`

Recovery keys are 32 random bytes that get base64-encoded to roughly 43
characters and rendered in groups of 4 for the user. We store an Argon2id hash
of the binary key, so we can verify a candidate key without being able to
recover the original. The hash is via PHP's `password_hash(PASSWORD_ARGON2ID)`
rather than libsodium — the parameters are deliberately lighter (memory_cost
65536 / time_cost 4) because the input is already 256 bits of entropy and
brute-forcing it is computationally infeasible. Pinning the parameters ensures
verification cost stays bounded.

## The split-key VMK in detail

The threat we're defending against is *partial* compromise — the attacker gets
the database, or the session store, or the user's cookies, but not all three.
Storing the unlocked VMK only in the session would mean a full session store
dump is enough to read every active user's vault; storing it only in a cookie
would mean any XSS could grab it. Splitting it makes both targets necessary.

### Sequence: store

```
unlock()
  ├─ derive KEK from password
  ├─ decrypt VMK from vault_headers (KEK)
  └─ storeVmkInSession(vmk):
       ├─ session_key = random 32 bytes
       ├─ nonce       = random 24 bytes
       ├─ session.put('vaultable.encrypted_vmk', base64( AEAD(vmk, session_key, nonce) ))
       ├─ session.put('vaultable.vmk_nonce',     base64( nonce ))
       ├─ session.put('vaultable.unlock_time',   time())
       ├─ cookie.queue('vaultable_session_key',  base64( session_key ),
       │                                        secure=true, httpOnly=true,
       │                                        sameSite='Lax')
       └─ sodium_memzero(session_key)
```

Three things to notice:

1. The `session_key` is wiped from memory after the cookie is queued, so it
   exists only on the wire and in the client's cookie jar.
2. The cookie is `Secure` (HTTPS only), `HttpOnly` (no JS access), and
   `SameSite=Lax` (defends against most CSRF-style cross-site requests). It
   does **not** specify a `Domain`, so it stays on the application's exact
   host.
3. `unlock_time` is updated every time `getVmk()` is called. This is what
   makes the session timeout a sliding window of inactivity rather than a
   fixed lifetime from login.

### Sequence: read

```
getVmk()
  ├─ require isUnlocked()
  ├─ touch unlock_time
  └─ decryptVmkFromSession():
       ├─ session_key   = base64_decode( request.cookie('vaultable_session_key') )
       ├─ encrypted_vmk = base64_decode( session.get('vaultable.encrypted_vmk') )
       ├─ nonce         = base64_decode( session.get('vaultable.vmk_nonce') )
       └─ AEAD.decrypt(encrypted_vmk, session_key, nonce) ──► vmk
```

### Same-request access

A subtle bug we already worked around: when the cookie is *queued* during a
request (e.g. on login), it isn't in `Request::cookie()` yet — that only sees
incoming cookies, not outgoing ones. `getSessionKeyFromCookie()` falls back
to scanning the queued-cookies bag so that calling `getVmk()` *during* the
same request that just unlocked the vault still works.

## File-by-file tour

```
src/
├── Actions/Fortify/
│   ├── CreateNewUserWithVault.php          decorator: CreatesNewUsers
│   ├── ResetUserPasswordWithVault.php      decorator: ResetsUserPasswords
│   ├── TwoFactorAuthWithVault.php          replacement: RedirectIfTwoFactorAuthenticatable
│   ├── UnlockVaultOnLogin.php              new pipeline stage, runs at the tail
│   └── UpdateUserPasswordWithVault.php     decorator: UpdatesUserPasswords
├── Casts/
│   └── VaultedString.php                   Eloquent cast wrapping encrypt/decrypt
├── Contracts/
│   └── VaultServiceInterface.php           public surface; everything else is internal
├── Crypto/
│   ├── AeadEncryption.php                  thin XChaCha20-Poly1305 wrapper
│   └── KeyDerivation.php                   Argon2id + optional HMAC-SHA256 pepper
├── Enums/
│   ├── AeadAlgorithm.php                   on-disk algorithm tag
│   └── KdfAlgorithm.php                    on-disk algorithm tag (Argon2id only today)
├── Events/
│   ├── VaultCreated.php                    after createVault()
│   ├── VaultLocked.php                     after lockVault()
│   ├── VaultRecoveryKeyGenerated.php       contains the only plaintext copy
│   └── VaultUnlocked.php                   after a successful unlockVault()
├── Exceptions/
│   ├── RecoveryKeyRequiredException.php    422-style: missing/invalid recovery key
│   ├── VaultDecryptionFailedException.php  AEAD auth-tag failure
│   ├── VaultException.php                  base
│   └── VaultLockedException.php            getVmk() / middleware on a locked vault
├── Facades/
│   └── Vault.php                           static-syntax wrapper around VaultServiceInterface
├── Http/Middleware/
│   └── EnsureVaultUnlocked.php             route guard; aliased as 'vault.unlocked'
├── Models/
│   ├── VaultHeader.php                     one per vaultable, stores the encrypted VMK
│   └── VaultRecoveryKey.php                zero/one per header, stores recovery wrap
├── Services/
│   ├── RecoveryKeyService.php              generate, verify, recover, format, parse
│   └── VaultService.php                    create, unlock, lock, isUnlocked, getVmk, rotateKek
├── Traits/
│   └── HasVault.php                        enables the polymorphic relation + Fortify hooks
└── ServiceProvider.php                     wires everything
```

### `KeyDerivation`

Two important methods:

- `deriveKey()` runs `sodium_crypto_pwhash` with the stored Argon2id parameters.
  The salt is per-vault, regenerated on every KDF rotation.
- `needsRehash()` compares the parameters stored in the row with the current
  config. If they differ, the next successful unlock triggers
  `VaultService::upgradeKdfParameters()`.

Pepper application is intentionally inside `KeyDerivation` (not somewhere
higher in the call stack) so that nothing else has to think about it. The
pepper is a constructor argument; the service provider injects it from config.

### `AeadEncryption`

Public methods are `generateNonce`, `generateKey`, `encrypt`, `decrypt`. All
four wrap libsodium directly. `decrypt` translates a `false` return from
`sodium_crypto_aead_xchacha20poly1305_ietf_decrypt` into a typed
`VaultDecryptionFailedException` so callers can catch it predictably.

The constants `KEY_LENGTH`, `NONCE_LENGTH`, and `TAG_LENGTH` are exported so
external callers (e.g. the [VaultedString cast recipe](../README.md#encrypted-eloquent-attribute-recipe))
can do nonce/ciphertext slicing without hard-coding numbers.

### `VaultService`

The orchestrator. Public methods are exactly the
[`VaultServiceInterface`](../src/Contracts/VaultServiceInterface.php) surface:
`createVault`, `unlockVault`, `lockVault`, `isUnlocked`, `getVmk`,
`rotateKek`, `encrypt`, `decrypt`.

`encrypt()` and `decrypt()` are convenience helpers for application data.
They generate a fresh nonce per call, run XChaCha20-Poly1305 against the
unlocked VMK, and pack the output as base64(`nonce` ‖ `ciphertext`) so a
single column round-trips losslessly. Both wipe the local VMK copy with
`sodium_memzero` after use.

Internally `VaultService` owns the session/cookie storage scheme. The session
keys are constants on the class (`SESSION_ENCRYPTED_VMK_KEY`,
`SESSION_VMK_NONCE_KEY`, `SESSION_UNLOCK_TIME_KEY`) and the cookie name is
`vaultable_session_key`.

### `VaultedString` cast

A thin Eloquent `CastsAttributes` implementation that calls
`VaultService::encrypt` on `set` and `VaultService::decrypt` on `get`. Null
passes through untouched. Anything else is coerced to a string before
encryption.

Reading or writing a vaulted attribute throws `VaultLockedException` if no
vault is unlocked — important for understanding queue behaviour, since a
queued job that hydrates a model with vaulted attributes will throw the
moment it touches one.

### `RecoveryKeyService`

Holds the recovery-specific code: generate, verify, recover, format, parse,
delete. Worth knowing:

- `generateRecoveryKey()` always `updateOrCreate`s — calling it twice replaces
  the previous recovery key, since you'd expect the *current* user-visible
  string to be the only valid one.
- `formatRecoveryKey()` strips base64 padding and groups in 4-character
  chunks. `parseRecoveryKey()` reverses that. The whitespace is purely
  cosmetic; the parser tolerates any layout.
- `verifyRecoveryKey()` accepts either a 32-byte raw key or a formatted
  string and dispatches accordingly.

### `HasVault`

Two responsibilities:

1. Declares the `morphOne` relation to `VaultHeader`.
2. Acts as a **marker** — the Fortify decorators check
   `class_uses_recursive($model)` for this trait before doing anything. A
   model that doesn't use `HasVault` flows through Fortify untouched, even
   when the package is installed.

This is what makes selective adoption possible (e.g. only certain user types
get vaults).

### `ServiceProvider`

Two phases:

`register()` is binding-only:

```php
$this->mergeConfigFrom(...);
$this->registerCryptoServices();   // KeyDerivation, AeadEncryption singletons
$this->registerVaultService();     // VaultServiceInterface + alias
$this->registerRecoveryKeyService();
```

`boot()` does runtime wiring:

```php
$this->validateSessionDriver();    // throws on cookie / array (outside tests)
$this->publishAssets();            // config + migrations publish tags
$this->registerMorphMap();         // Relation::morphMap from config
$this->registerMiddleware();       // 'vault.unlocked' alias
$this->registerLogoutListener();   // Auth Logout → lockVault()
if (Fortify present && auto_integrate) {
    $this->extendFortifyContracts();
    $this->registerAuthenticationPipeline();
}
```

The Fortify integration is fenced behind `class_exists(Fortify::class)`, so
the package will boot fine in apps that don't use Fortify — they just lose
the auto-integration and have to use the manual API.

## Fortify integration deep-dive

Fortify exposes a handful of contract bindings that an app can replace to
customise registration / password update / password reset / 2FA. The package
hooks these in two different ways depending on whether decoration is enough
or whether the action's behaviour fundamentally changes.

### Decoration via `$app->extend()`

For `CreatesNewUsers`, `UpdatesUserPasswords`, and `ResetsUserPasswords`, the
package wraps whatever the application has bound:

```php
$this->app->extend(CreatesNewUsers::class, function ($service, $app) {
    return new CreateNewUserWithVault(
        createNewUser: $service,
        ...
    );
});
```

This is important: the host app's existing action (e.g. `App\Actions\Fortify\CreateNewUser`)
remains on the **inside** of the decorator and runs first. The package only
ever adds vault behaviour around the host's logic, never replaces it.

In a stock Jetstream app the order ends up being:

```
Fortify::createUsersUsing(App\…\CreateNewUser::class)   // app boots, binds host action
  → ServiceProvider::boot() runs, $app->extend wraps it with CreateNewUserWithVault
  → resolution returns: CreateNewUserWithVault( CreateNewUser )
```

> **Provider order matters.** `$app->extend()` only wraps a binding that's
> already present. The package's `ServiceProvider` is loaded via package
> discovery, which happens *after* the application's own providers register
> but the runtime order in `boot()` is mediated by Laravel's deferred boot
> queue. In practice this works because both bindings happen during
> `register()`, and `extend()` runs at boot. If you ever rebind the contract
> *after* boot, the package won't be in the chain — don't do that.

### Pipeline modification

The login pipeline is rebuilt via `Fortify::authenticateThrough()` because we
need to (a) replace `RedirectIfTwoFactorAuthenticatable` with our own version
that captures the password before redirecting, and (b) append
`UnlockVaultOnLogin` at the tail.

The replacement is conditional — we only insert our 2FA action if
`Features::enabled(Features::twoFactorAuthentication())`. Apps without 2FA
get a leaner pipeline.

```php
$pipeline = [
    EnsureLoginIsNotThrottled::class | null   // fortify.limiters.login decides
];
if (Features::enabled(Features::twoFactorAuthentication())) {
    $pipeline[] = TwoFactorAuthWithVault::class;
} // else: nothing — there's no Fortify default to keep
$pipeline[] = AttemptToAuthenticate::class;
$pipeline[] = PrepareAuthenticatedSession::class;
$pipeline[] = UnlockVaultOnLogin::class;
```

## Two-factor authentication flow

The challenge with 2FA is that the password arrives on the request that posts
the credentials, but the vault must be unlocked **after** the second factor
verifies — typically a separate request. We can't just stash the plaintext
password in the session.

Solution: an ephemeral key + secretbox.

```
First request: POST /login (email + password + maybe remember)
  TwoFactorAuthWithVault::handle()
    ├─ validate credentials (parent class)
    ├─ if user has 2FA configured:
    │    ├─ key   = random 32 bytes
    │    ├─ nonce = random 24 bytes
    │    ├─ session.put('vaultable.2fa_password', base64( nonce || secretbox(password, nonce, key) ))
    │    ├─ session.put('vaultable.2fa_key',      base64( key ))
    │    └─ return Fortify's twoFactorChallengeResponse
    └─ else: continue down the pipeline (AttemptToAuthenticate runs)

Second request: POST /two-factor-challenge (code or recovery)
  Fortify validates the code, logs the user in.
  TwoFactorAuthWithVault::unlockVaultAfterTwoFactor() retrieves and decrypts the password,
  unlocks the vault, then forgets the session keys and zeroes the key bytes.
```

This means the password is in the session for exactly the duration of the
2FA challenge — typically seconds — and the key needed to decrypt it is also
in the session, so neither half on its own is useful unless you have read
access to the entire session row. That's a weaker guarantee than the
[split-key VMK](#the-split-key-vmk-in-detail) but the window is much smaller.

A future improvement would be to move the 2FA key into a cookie too. The
reason it isn't already: the 2FA challenge typically *redirects* the user, and
mid-redirect is exactly the worst time to try to reason about cookie
visibility. The current approach is correct under all browsers and proxies.

## KDF auto-upgrade

`config('vaultable.kdf')` represents what we want to use *now*. Existing
vaults stored their parameters in the row. On every successful unlock we
compare:

```php
if ($this->keyDerivation->needsRehash($stored, $current)) {
    $this->upgradeKdfParameters($vaultHeader, $vmk, $password);
}
```

`upgradeKdfParameters()` regenerates the salt and nonce, derives a new KEK at
the *current* parameters, re-encrypts the VMK with that KEK, and writes the
header. The user notices nothing — their next login is the same.

Because the salt rotates, this also gives us defence-in-depth against rainbow
tables built against an old salt. Auto-upgrade only kicks in on a
*successful* unlock, so a wrong-password attempt doesn't accidentally trigger
a write.

## Recovery keys

The recovery flow is a parallel encryption of the same VMK under a different
secret. At creation time, with a plaintext VMK in hand, we generate a 32-byte
recovery key, encrypt the VMK under it, and store both the ciphertext and the
recovery key's Argon2id hash.

```
generate:
  recovery_key    = random 32 bytes
  recovery_nonce  = random 24 bytes
  recovery_cipher = AEAD(vmk, recovery_key, recovery_nonce)
  recovery_hash   = password_hash(recovery_key, ARGON2ID)
  vault_recovery_keys.upsert(...)
  emit VaultRecoveryKeyGenerated(model, format(recovery_key))

recover:
  recovery_key    = parse(input)
  password_verify(recovery_key, stored_hash)  // gate
  vmk             = AEAD.decrypt(recovery_cipher, recovery_key, recovery_nonce)
  rotate KDF: new_salt, new_nonce, new_kek = KDF(new_password, new_salt, …)
  vault_headers.update(... AEAD(vmk, new_kek, new_nonce) ...)
```

The hash isn't strictly necessary for security — a wrong key would fail at
the AEAD step anyway — but it lets us short-circuit cleanly with a clear
error before doing any expensive crypto. It also avoids leaking timing
information about which step failed.

The recovery row is not deleted on use; it remains valid for repeat use
until explicitly rotated. This is a deliberate UX call: a user who recovered
once should not need to immediately generate and save a new recovery key.

## Sessions, cookies, and request boundaries

Two pieces of state drive everything:

| Where        | Key                              | Purpose                                            |
|--------------|----------------------------------|----------------------------------------------------|
| Session      | `vaultable.encrypted_vmk`        | base64(AEAD ciphertext of VMK under session_key)   |
| Session      | `vaultable.vmk_nonce`            | base64(nonce used for that AEAD)                   |
| Session      | `vaultable.unlock_time`          | unix timestamp; sliding window for timeout         |
| Session (2FA)| `vaultable.2fa_password`         | base64(nonce || secretbox(password))               |
| Session (2FA)| `vaultable.2fa_key`              | base64(key for the secretbox above)                |
| Cookie       | `vaultable_session_key`          | base64(32-byte session_key); HttpOnly, Secure, Lax |

The cookie's lifetime is `ceil(session_timeout / 60)` minutes when the timeout
is positive; otherwise the cookie is a session cookie (cleared when the
browser closes).

Inactivity timeout is enforced inside `isUnlocked()`. If `time() - unlock_time
> sessionTimeout`, the vault is locked immediately and `isUnlocked()` returns
false. There's no separate scheduler — the next request after the window
expires is what triggers the lock.

## Logout and locking

Two paths:

1. **Auth `Logout` event.** The service provider registers a listener that
   calls `lockVault()` whenever Laravel fires `Illuminate\Auth\Events\Logout`.
   This covers `Auth::logout()`, Fortify's logout endpoint, and anything else
   that triggers the standard event.
2. **Inactivity.** `isUnlocked()` itself calls `lockVault()` when the timeout
   has elapsed.

`lockVault()` does three things: forgets the three session keys, queues the
session-key cookie for forgetting, and emits `VaultLocked`. There is no
in-memory cleanup beyond that because the service is request-scoped through
the container and the VMK is never held by any object — `getVmk()` returns
fresh from the session every time.

## Testing strategy

The suite uses Orchestra Testbench to spin up a Laravel-like environment in
the package itself.

| File                                                     | Covers                                                           |
|----------------------------------------------------------|------------------------------------------------------------------|
| `tests/Unit/Crypto/KeyDerivationTest.php`                | KDF correctness, salt randomness, pepper application, rehash check |
| `tests/Unit/Crypto/AeadEncryptionTest.php`               | Round-trips, tampered ciphertext, wrong key, nonce uniqueness    |
| `tests/Unit/ServiceProviderTest.php`                     | Bindings, middleware alias, morph map, session-driver guard      |
| `tests/Feature/Models/VaultHeaderTest.php`               | Polymorphic relation, attribute casts (binary base64 round-trip) |
| `tests/Feature/Services/VaultServiceTest.php`            | End-to-end create/unlock/lock/rotate, KDF auto-upgrade           |
| `tests/Feature/Services/RecoveryKeyServiceTest.php`      | Generate, verify, recover, format/parse round-trip               |
| `tests/Feature/Traits/HasVaultTest.php`                  | Trait behaviour on a fixture model                               |

Notable testing patterns used:

- **Encryption invariants over equality.** AEAD output is non-deterministic
  (random nonces). Tests assert that `decrypt(encrypt(x)) == x` and that
  changing one byte of the ciphertext makes decryption fail, rather than
  comparing ciphertexts to fixed bytes.
- **No mocking of crypto.** Crypto primitives are tested against libsodium
  directly. Mocking them would prove only that PHP can call PHP.
- **Real session driver.** Feature tests use Testbench's `array` driver,
  which the service provider explicitly permits inside
  `runningUnitTests()`.

## Extension points

### Adding a new vaultable model

```php
// In your app's config/vaultable.php
'models' => [
    'user'    => App\Models\User::class,
    'patient' => App\Models\Patient::class,
],

// On the model
use DigitalGrease\Vaultable\Traits\HasVault;

class Patient extends Model
{
    use HasVault;
}
```

The morph map alias (`'patient'`) is what `vaultable_type` will store. Pick
short, stable strings.

### Custom KDF / AEAD

Both `KeyDerivation` and `AeadEncryption` are concrete classes bound as
singletons. To swap them, override the binding in your own service provider
*after* the package has registered:

```php
$this->app->singleton(KeyDerivation::class, fn () => new MyKdf(...));
```

The on-disk algorithm tags (`KdfAlgorithm`, `AeadAlgorithm`) are enums. If you
add a new algorithm you'll need to extend the enum and teach the service
classes to dispatch on it. The current `VaultService` is hard-wired to
Argon2id + XChaCha20-Poly1305 because there are no other defensible choices
yet.

### Custom Fortify integration

Set `vaultable.fortify.auto_integrate = false` and call the service yourself
from your application's Fortify actions. The README's
[manual operations section](../README.md#manual-vault-operations) shows the
full surface.

### Listening to events

`VaultCreated`, `VaultUnlocked`, `VaultLocked`, and
`VaultRecoveryKeyGenerated` use Laravel's `Dispatchable` + `SerializesModels`
traits. They can be listened to with the standard `Event::listen()` /
`#[AsEventListener]` / EventServiceProvider mechanisms.

`VaultRecoveryKeyGenerated` is the only place the plaintext recovery key is
ever observable. If you don't capture it in a listener, it's gone.

## Known limitations

- **Password is read from the request.** `UnlockVaultOnLogin` reads
  `request.input('password')` to derive the KEK. If your custom login form
  uses a different field name, the back-fill won't fire and the user will
  log in without a vault. (The fix: pass the correct field name through, or
  call `unlockVault()` manually.)
- **No batch re-keying.** If you change `VAULTABLE_PEPPER`, every vault is
  invalidated and there's no migration tool.
- **No background-job decryption path.** Intentional — see
  [Goals and non-goals](#goals-and-non-goals).
- **`VaultUnlocked` event has no payload for the password.** This is
  deliberate — leaking the password to listeners would defeat the model.

## Roadmap

Probable next moves, in rough order:

1. Tag the first 0.1.0 release.
2. Add Sanctum/Passport integration so API tokens can carry a re-derivable
   "vault session" without password re-entry on every request. (Hard. Worth
   thinking through carefully.)
3. Add a re-key console command for the day someone *does* need to rotate the
   pepper.
4. Add a `VaultedJson` / `VaultedEncrypted<T>` cast so structured data can be
   stored without callers having to JSON-encode by hand.
