<?php

namespace DigitalGrease\Vaultable\Tests\Feature\Traits;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Models\VaultHeader;
use DigitalGrease\Vaultable\Tests\Fixtures\Models\User;
use DigitalGrease\Vaultable\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class HasVaultTest extends TestCase
{
    #[Test]
    public function it_can_check_if_model_has_vault(): void
    {
        $user = User::factory()->create();

        $this->assertFalse($user->hasVault());

        $vaultService = $this->app->make(VaultServiceInterface::class);
        $vaultService->createVault($user, 'password123');

        $this->assertTrue($user->hasVault());
    }

    #[Test]
    public function it_provides_vault_header_relationship(): void
    {
        $vaultService = $this->app->make(VaultServiceInterface::class);
        $user = User::factory()->create();
        $vaultService->createVault($user, 'password123');

        $vaultHeader = $user->vaultHeader;

        $this->assertInstanceOf(VaultHeader::class, $vaultHeader);
    }

    #[Test]
    public function it_returns_null_when_no_vault_exists(): void
    {
        $user = User::factory()->create();

        $vaultHeader = $user->vaultHeader;

        $this->assertNull($vaultHeader);
    }
}
