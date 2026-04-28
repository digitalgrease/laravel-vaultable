<?php

namespace DigitalGrease\Vaultable\Tests\Feature\Services;

use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Events\VaultCreated;
use DigitalGrease\Vaultable\Events\VaultLocked;
use DigitalGrease\Vaultable\Events\VaultUnlocked;
use DigitalGrease\Vaultable\Exceptions\VaultDecryptionFailedException;
use DigitalGrease\Vaultable\Exceptions\VaultLockedException;
use DigitalGrease\Vaultable\Tests\Fixtures\Models\User;
use DigitalGrease\Vaultable\Tests\TestCase;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\Test;

class VaultServiceTest extends TestCase
{
    protected VaultServiceInterface $vaultService;

    protected function setUp(): void
    {
        parent::setUp();
        $this->vaultService = $this->app->make(VaultServiceInterface::class);
    }

    #[Test]
    public function it_creates_vault_for_user(): void
    {
        Event::fake();
        $user = User::factory()->create();

        $vaultHeader = $this->vaultService->createVault($user, 'password123');

        $this->assertNotNull($vaultHeader);
        $this->assertTrue($user->hasVault());
        $this->assertDatabaseHas('vault_headers', [
            'vaultable_id' => $user->id,
        ]);
        Event::assertDispatched(VaultCreated::class);
    }

    #[Test]
    public function it_stores_vmk_in_session_after_creation(): void
    {
        $user = User::factory()->create();

        $this->vaultService->createVault($user, 'password123');

        $this->assertTrue($this->vaultService->isUnlocked());
        $this->assertNotNull($this->vaultService->getVmk());
    }

    #[Test]
    public function it_unlocks_vault_with_correct_password(): void
    {
        Event::fake();
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');
        $this->vaultService->lockVault();

        $result = $this->vaultService->unlockVault($user, 'password123');

        $this->assertTrue($result);
        $this->assertTrue($this->vaultService->isUnlocked());
        Event::assertDispatched(VaultUnlocked::class);
    }

    #[Test]
    public function it_fails_to_unlock_vault_with_wrong_password(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');
        $this->vaultService->lockVault();

        $result = $this->vaultService->unlockVault($user, 'wrong-password');

        $this->assertFalse($result);
        $this->assertFalse($this->vaultService->isUnlocked());
    }

    #[Test]
    public function it_locks_vault(): void
    {
        Event::fake();
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');

        $this->vaultService->lockVault();

        $this->assertFalse($this->vaultService->isUnlocked());
        Event::assertDispatched(VaultLocked::class);
    }

    #[Test]
    public function it_throws_exception_when_getting_vmk_from_locked_vault(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');
        $this->vaultService->lockVault();

        $this->expectException(VaultLockedException::class);
        $this->vaultService->getVmk();
    }

    #[Test]
    public function it_rotates_kek_with_new_password(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');
        $vmkBefore = $this->vaultService->getVmk();

        $result = $this->vaultService->rotateKek($user, 'password123', 'new-password');

        $this->assertTrue($result);
        $vmkAfter = $this->vaultService->getVmk();
        $this->assertSame($vmkBefore, $vmkAfter);

        $this->vaultService->lockVault();
        $this->assertTrue($this->vaultService->unlockVault($user, 'new-password'));
        $this->assertFalse($this->vaultService->unlockVault($user, 'password123'));
    }

    #[Test]
    public function it_fails_to_rotate_kek_with_wrong_old_password(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');

        $result = $this->vaultService->rotateKek($user, 'wrong-password', 'new-password');

        $this->assertFalse($result);
    }

    #[Test]
    public function it_returns_false_when_unlocking_non_existent_vault(): void
    {
        $user = User::factory()->create();

        $result = $this->vaultService->unlockVault($user, 'password123');

        $this->assertFalse($result);
    }

    #[Test]
    public function it_preserves_vmk_across_kek_rotation(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');
        $originalVmk = $this->vaultService->getVmk();

        $this->vaultService->rotateKek($user, 'password123', 'new-password');
        $vmkAfterRotation = $this->vaultService->getVmk();

        $this->assertSame($originalVmk, $vmkAfterRotation);
    }

    #[Test]
    public function it_round_trips_application_data_through_encrypt_and_decrypt(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');

        $plaintext = 'super secret note';
        $encoded = $this->vaultService->encrypt($plaintext);

        $this->assertNotSame($plaintext, $encoded);
        $this->assertSame($plaintext, $this->vaultService->decrypt($encoded));
    }

    #[Test]
    public function it_produces_a_different_ciphertext_each_time_for_the_same_plaintext(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');

        $a = $this->vaultService->encrypt('same input');
        $b = $this->vaultService->encrypt('same input');

        $this->assertNotSame($a, $b);
    }

    #[Test]
    public function it_round_trips_an_empty_string(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');

        $encoded = $this->vaultService->encrypt('');

        $this->assertSame('', $this->vaultService->decrypt($encoded));
    }

    #[Test]
    public function it_throws_when_encrypting_with_a_locked_vault(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');
        $this->vaultService->lockVault();

        $this->expectException(VaultLockedException::class);
        $this->vaultService->encrypt('anything');
    }

    #[Test]
    public function it_throws_when_decrypting_with_a_locked_vault(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');
        $encoded = $this->vaultService->encrypt('payload');
        $this->vaultService->lockVault();

        $this->expectException(VaultLockedException::class);
        $this->vaultService->decrypt($encoded);
    }

    #[Test]
    public function it_throws_on_malformed_ciphertext(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');

        $this->expectException(VaultDecryptionFailedException::class);
        $this->vaultService->decrypt('not-a-valid-blob');
    }

    #[Test]
    public function it_throws_on_tampered_ciphertext(): void
    {
        $user = User::factory()->create();
        $this->vaultService->createVault($user, 'password123');
        $encoded = $this->vaultService->encrypt('payload');

        $tampered = base64_encode(base64_decode($encoded) ^ str_repeat("\x01", strlen(base64_decode($encoded))));

        $this->expectException(VaultDecryptionFailedException::class);
        $this->vaultService->decrypt($tampered);
    }
}
