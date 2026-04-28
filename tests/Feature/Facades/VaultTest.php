<?php

namespace DigitalGrease\Vaultable\Tests\Feature\Facades;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Facades\Vault;
use DigitalGrease\Vaultable\Tests\Fixtures\Models\User;
use DigitalGrease\Vaultable\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class VaultTest extends TestCase
{
    #[Test]
    public function it_resolves_to_the_vault_service_binding(): void
    {
        $this->assertSame(
            $this->app->make(VaultServiceInterface::class),
            Vault::getFacadeRoot(),
        );
    }

    #[Test]
    public function it_round_trips_data_through_the_facade(): void
    {
        $user = User::factory()->create();
        Vault::createVault($user, 'password123');

        $encoded = Vault::encrypt('hello via facade');

        $this->assertSame('hello via facade', Vault::decrypt($encoded));
    }

    #[Test]
    public function it_reports_unlocked_state_through_the_facade(): void
    {
        $user = User::factory()->create();
        Vault::createVault($user, 'password123');

        $this->assertTrue(Vault::isUnlocked());

        Vault::lockVault();

        $this->assertFalse(Vault::isUnlocked());
    }
}
