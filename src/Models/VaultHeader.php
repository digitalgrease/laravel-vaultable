<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class VaultHeader extends Model
{
    use HasFactory;

    // Fields
    // - id
    // - version (int)
    // - kdf_algorithm (string) (argon2id)
    // - kdf_version (int) (19)
    // - kdf_salt (string)
    // - kdf_iterations (int)
    // - kdf_memory_cost (int)
    // - aead_algorithm (string) (xchacha20-poly1305)
    // - aead_nonce (string)
    // - encrypted_vmk (string)
    // - created_at
    // - updated_at

    // Generate KEK Salt:
    // - $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    // - store as base64 encoded string

    // Pre-process the user password with pepper:
    // - $pepper = getenv('APP_PEPPER');  // keep in env / KMS, NOT in DB
    // - $pw_input = hash_hmac('sha256', $userPassword, $pepper, true);

    // Generate KEK from user password:
    // - sodium_crypto_pwhash
    // - Argon2id
    // - key length is dependent on the encryption algo the key is to be used with (SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES)
    // - memory cost SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE
    // - time cost SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE
    // $kek = sodium_crypto_pwhash(
    //     SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
    //     $userPassword,                            // string
    //     $salt,
    //     SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,   // tuning knobs
    //     SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
    //     SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    // );

    // Generate VMK:
    // - 32 bytes
    // - cryptographically secure random bytes (CSPRNG?)

    // Encrypt VMK:
    // - XChaCha20-Poly1305
    // - serialise immutable vault header fields into canonical and stable string for associated data
    // $headerMetadata = [
    //     'version' => 1,
    //     'created' => time(),
    //     // ... other metadata
    // ];
    // // IMPORTANT: use a stable, canonical encoding.
    // // E.g. JSON with sorted keys, or a fixed binary struct.
    // $aad = json_encode($headerMetadata, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    // - generate 24 byte random nonce
    // - $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    // - sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()
    // $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
    //     $vmk,
    //     $aad,
    //     $nonce,
    //     $kek
    // );
    // - store the nonce and encrypted VMK in the vault header

    // Updating KEK:
    // Rather than trying to guess "future-proof" numbers now, design your system so you can ratchet the parameters up over time:
	// 1.	Always store: KDF algorithm, opslimit, memlimit, salt.
	// 2.	When the user successfully authenticates or decrypts:
	// - Check if the stored parameters are below your current recommended baseline.
	// - If so, re-derive a KEK with stronger parameters and re-encrypt / re-store as needed.
	// - Periodically revise your "baseline" to, say, 2–4× the CPU or memory cost when hardware improves or new guidance lands.
    // Libsodium also has sodium_crypto_pwhash_str_needs_rehash() for password hashes that encapsulate parameters; you can mirror the same idea manually for your KEK metadata

    // EXAMPLE CODE:
    // Schema::create('vault_headers', function (Blueprint $table) {
    //     $table->id();
        
    //     // Polymorphic owner of this vault
    //     $table->nullableMorphs('vaultable'); 
    //     // creates vaultable_type + vaultable_id indexed
    
    //     // Encrypted master key material
    //     $table->text('encrypted_master_key');
    //     $table->string('encryption_algorithm')->default('aes-256-gcm');
    //     $table->unsignedInteger('key_version')->default(1);
    
    //     // Optional metadata
    //     $table->json('meta')->nullable();
        
    //     $table->timestamps();
    
    //     // Optional uniqueness per owner
    //     $table->unique(['vaultable_type', 'vaultable_id'], 'vaultable_unique');
    // });

    // MODEL
    // use Illuminate\Database\Eloquent\Model;
    // use Illuminate\Database\Eloquent\Relations\MorphTo;
    
    // class VaultHeader extends Model
    // {
    //     protected $fillable = [
    //         'encrypted_master_key',
    //         'encryption_algorithm',
    //         'key_version',
    //         'meta',
    //     ];
    
    //     protected $casts = [
    //         'meta' => 'array',
    //     ];
    
    //     public function vaultable(): MorphTo
    //     {
    //         return $this->morphTo();
    //     }
    // }

    // TRAIT
    // use Illuminate\Database\Eloquent\Relations\MorphOne;

    // trait HasVault
    // {
    //     public function vault(): MorphOne
    //     {
    //         return $this->morphOne(VaultHeader::class, 'vaultable');
    //     }
    // }

    // USE CASES
    // class User extends Authenticatable
    // {
    //     use HasVault;
    // }
    
    // class Team extends Model
    // {
    //     use HasVault;
    // }

    // $vault = $vaultManager->for($user)->getOrCreateVault();
    // $vault = $vaultManager->for($team)->rotateKey();

    // $user->vault()->encrypt($data);
    // $vaultManager->for($model)->encrypt($data);
    // $vaultManager->for($model)->decrypt($ciphertext);
    // $vaultManager->for($model)->rotate();

    // ON LOGIN
    // $credentials = $request->only('email', 'password');

    // if (Auth::attempt($credentials, $request->filled('remember'))) {

    //     // 1. You still have the password here
    //     $password = $credentials['password'];

    //     // 2. Derive KEK from password (e.g. using Argon2 or PBKDF2)
    //     $kek = app(\App\Services\CryptoService::class)->deriveKekFromPassword($password);

    //     // 3. Decrypt VMK from DB (e.g. on the User model)
    //     $encryptedVmk = Auth::user()->encrypted_vmk;
    //     $vmk = app(\App\Services\CryptoService::class)->decryptVmk($encryptedVmk, $kek);

    //     // 4. Store VMK & last unlock time in session
    //     session([
    //         'vault_vmk'         => base64_encode($vmk),
    //         'vault_last_unlock' => time(),
    //     ]);

    //     return redirect()->intended('/dashboard');
    // }

    // return back()->withErrors([
    //     'email' => 'These credentials do not match our records.',
    // ]);

    // ON LOGOUT
    // public function logout(Request $request)
    // {
    //     Auth::logout();
    
    //     // Clear VMK from session
    //     $request->session()->forget(['vault_vmk', 'vault_last_unlock']);
    //     $request->session()->invalidate();
    //     $request->session()->regenerateToken();
    
    //     return redirect('/');
    // }

    // MIDDLEWARE
    // namespace App\Http\Middleware;

    // use Closure;
    // use Illuminate\Http\Request;
    
    // class EnsureVaultUnlocked
    // {
    //     public function handle(Request $request, Closure $next)
    //     {
    //         $vmk = $request->session()->get('vault_vmk');
    //         $lastUnlock = $request->session()->get('vault_last_unlock');
    
    //         // Optional idle timeout (e.g. 15 minutes)
    //         $maxIdle = 15 * 60;
    
    //         if (!$vmk || !$lastUnlock || (time() - $lastUnlock) > $maxIdle) {
    //             // Clear any stale values
    //             $request->session()->forget(['vault_vmk', 'vault_last_unlock']);
    
    //             // Redirect to a "Unlock Vault" page that asks for password again
    //             return redirect()->route('vault.unlock');
    //         }
    
    //         return $next($request);
    //     }
    // }
}
