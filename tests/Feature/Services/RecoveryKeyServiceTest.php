<?php

namespace DigitalGrease\Vaultable\Tests\Feature\Services;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Events\VaultRecoveryKeyGenerated;
use DigitalGrease\Vaultable\Services\RecoveryKeyService;
use DigitalGrease\Vaultable\Tests\Fixtures\Models\User;
use DigitalGrease\Vaultable\Tests\TestCase;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\Test;

class RecoveryKeyServiceTest extends TestCase
{
    protected VaultServiceInterface $vaultService;

    protected RecoveryKeyService $recoveryKeyService;

    protected function setUp(): void
    {
        parent::setUp();
        $this->vaultService = $this->app->make(VaultServiceInterface::class);
        $this->recoveryKeyService = $this->app->make(RecoveryKeyService::class);
    }

    #[Test]
    public function it_generates_recovery_key(): void
    {
        Event::fake();
        $user = User::factory()->create();
        $vaultHeader = $this->vaultService->createVault($user, 'password123');
        $vmk = $this->vaultService->getVmk();

        $recoveryKey = $this->recoveryKeyService->generateRecoveryKey($vaultHeader, $vmk);

        $this->assertNotEmpty($recoveryKey);
        $this->assertDatabaseHas('vault_recovery_keys', [
            'vault_header_id' => $vaultHeader->id,
        ]);
        Event::assertDispatched(VaultRecoveryKeyGenerated::class);
    }

    #[Test]
    public function it_formats_recovery_key_with_spaces(): void
    {
        $user = User::factory()->create();
        $vaultHeader = $this->vaultService->createVault($user, 'password123');
        $vmk = $this->vaultService->getVmk();

        $recoveryKey = $this->recoveryKeyService->generateRecoveryKey($vaultHeader, $vmk);

        $this->assertStringContainsString(' ', $recoveryKey);
    }

    #[Test]
    public function it_verifies_recovery_key(): void
    {
        $user = User::factory()->create();
        $vaultHeader = $this->vaultService->createVault($user, 'password123');
        $vmk = $this->vaultService->getVmk();
        $recoveryKey = $this->recoveryKeyService->generateRecoveryKey($vaultHeader, $vmk);
        $vaultHeader->refresh();

        $binaryKey = $this->recoveryKeyService->parseRecoveryKey($recoveryKey);
        $isValid = $this->recoveryKeyService->verifyRecoveryKey($vaultHeader, $binaryKey);

        $this->assertTrue($isValid);
    }

    #[Test]
    public function it_fails_to_verify_wrong_recovery_key(): void
    {
        $user = User::factory()->create();
        $vaultHeader = $this->vaultService->createVault($user, 'password123');
        $vmk = $this->vaultService->getVmk();
        $this->recoveryKeyService->generateRecoveryKey($vaultHeader, $vmk);
        $vaultHeader->refresh();

        $wrongKey = random_bytes(32);
        $isValid = $this->recoveryKeyService->verifyRecoveryKey($vaultHeader, $wrongKey);

        $this->assertFalse($isValid);
    }

    #[Test]
    public function it_recovers_vault_with_recovery_key(): void
    {
        $user = User::factory()->create();
        $vaultHeader = $this->vaultService->createVault($user, 'password123');
        $vmk = $this->vaultService->getVmk();
        $recoveryKey = $this->recoveryKeyService->generateRecoveryKey($vaultHeader, $vmk);
        $this->vaultService->lockVault();

        $result = $this->recoveryKeyService->recoverWithKey($user, $recoveryKey, 'new-password');

        $this->assertTrue($result);

        $unlocked = $this->vaultService->unlockVault($user, 'new-password');
        $this->assertTrue($unlocked);
    }

    #[Test]
    public function it_fails_recovery_with_wrong_key(): void
    {
        $user = User::factory()->create();
        $vaultHeader = $this->vaultService->createVault($user, 'password123');
        $vmk = $this->vaultService->getVmk();
        $this->recoveryKeyService->generateRecoveryKey($vaultHeader, $vmk);

        $result = $this->recoveryKeyService->recoverWithKey($user, 'wrong-recovery-key', 'new-password');

        $this->assertFalse($result);
    }

    #[Test]
    public function it_parses_formatted_recovery_key(): void
    {
        $binaryKey = random_bytes(32);
        $formatted = $this->recoveryKeyService->formatRecoveryKey($binaryKey);

        $parsed = $this->recoveryKeyService->parseRecoveryKey($formatted);

        $this->assertSame($binaryKey, $parsed);
    }

    #[Test]
    public function it_deletes_recovery_key(): void
    {
        $user = User::factory()->create();
        $vaultHeader = $this->vaultService->createVault($user, 'password123');
        $vmk = $this->vaultService->getVmk();
        $this->recoveryKeyService->generateRecoveryKey($vaultHeader, $vmk);
        $vaultHeader->refresh();

        $result = $this->recoveryKeyService->deleteRecoveryKey($vaultHeader);

        $this->assertTrue($result);
        $this->assertDatabaseMissing('vault_recovery_keys', [
            'vault_header_id' => $vaultHeader->id,
        ]);
    }
}
