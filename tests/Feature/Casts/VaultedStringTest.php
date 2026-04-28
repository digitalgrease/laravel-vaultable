<?php

namespace DigitalGrease\Vaultable\Tests\Feature\Casts;

use DigitalGrease\Vaultable\Casts\VaultedString;
use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Exceptions\VaultLockedException;
use DigitalGrease\Vaultable\Tests\Fixtures\Models\User;
use DigitalGrease\Vaultable\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class VaultedStringTest extends TestCase
{
    protected VaultServiceInterface $vaultService;

    protected VaultedString $cast;

    protected function setUp(): void
    {
        parent::setUp();
        $this->vaultService = $this->app->make(VaultServiceInterface::class);
        $this->cast = new VaultedString;
    }

    #[Test]
    public function it_round_trips_a_string_attribute(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');

        $stored = $this->cast->set($user, 'note', 'hello vault', []);

        $this->assertNotSame('hello vault', $stored);
        $this->assertSame('hello vault', $this->cast->get($user, 'note', $stored, []));
    }

    #[Test]
    public function it_passes_through_null_on_set(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');

        $this->assertNull($this->cast->set($user, 'note', null, []));
    }

    #[Test]
    public function it_passes_through_null_on_get(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');

        $this->assertNull($this->cast->get($user, 'note', null, []));
    }

    #[Test]
    public function it_throws_on_set_when_vault_is_locked(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');
        $this->vaultService->lockVault();

        $this->expectException(VaultLockedException::class);
        $this->cast->set($user, 'note', 'cannot set', []);
    }

    #[Test]
    public function it_throws_on_get_when_vault_is_locked(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');
        $stored = $this->cast->set($user, 'note', 'will not read', []);
        $this->vaultService->lockVault();

        $this->expectException(VaultLockedException::class);
        $this->cast->get($user, 'note', $stored, []);
    }
}
