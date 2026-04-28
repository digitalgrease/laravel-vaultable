<?php

namespace DigitalGrease\Vaultable\Tests\Feature\Models;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Enums\AeadAlgorithm;
use DigitalGrease\Vaultable\Enums\KdfAlgorithm;
use DigitalGrease\Vaultable\Tests\Fixtures\Models\User;
use DigitalGrease\Vaultable\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class VaultHeaderTest extends TestCase
{
    #[Test]
    public function it_has_morphable_relationship_to_user(): void
    {
        $vaultService = $this->app->make(VaultServiceInterface::class);
        $user = User::factory()->create();

        $vaultHeader = $vaultService->createVault($user, 'password123');

        $this->assertTrue($vaultHeader->vaultable->is($user));
    }

    #[Test]
    public function it_casts_kdf_algorithm_to_enum(): void
    {
        $vaultService = $this->app->make(VaultServiceInterface::class);
        $user = User::factory()->create();

        $vaultHeader = $vaultService->createVault($user, 'password123');

        $this->assertInstanceOf(KdfAlgorithm::class, $vaultHeader->kdf_algorithm);
        $this->assertSame(KdfAlgorithm::ARGON2ID, $vaultHeader->kdf_algorithm);
    }

    #[Test]
    public function it_casts_aead_algorithm_to_enum(): void
    {
        $vaultService = $this->app->make(VaultServiceInterface::class);
        $user = User::factory()->create();

        $vaultHeader = $vaultService->createVault($user, 'password123');

        $this->assertInstanceOf(AeadAlgorithm::class, $vaultHeader->aead_algorithm);
        $this->assertSame(AeadAlgorithm::XCHACHA20_POLY1305, $vaultHeader->aead_algorithm);
    }

    #[Test]
    public function it_stores_binary_fields_as_base64(): void
    {
        $vaultService = $this->app->make(VaultServiceInterface::class);
        $user = User::factory()->create();

        $vaultHeader = $vaultService->createVault($user, 'password123');

        $this->assertSame(SODIUM_CRYPTO_PWHASH_SALTBYTES, strlen($vaultHeader->kdf_salt));
        $this->assertSame(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, strlen($vaultHeader->aead_nonce));
    }
}
