<?php

namespace DigitalGrease\Vaultable\Tests;

use DigitalGrease\Vaultable\ServiceProvider;
use DigitalGrease\Vaultable\Tests\Fixtures\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Orchestra\Testbench\Attributes\WithMigration;
use Orchestra\Testbench\TestCase as BaseTestCase;

#[WithMigration]
abstract class TestCase extends BaseTestCase
{
    use RefreshDatabase;

    protected function defineEnvironment($app): void
    {
        $app['config']->set('auth.providers.users.model', User::class);
        $app['config']->set('vaultable.fortify.auto_integrate', false);
        $app['config']->set('vaultable.pepper', 'test-pepper-for-testing');
        $app['config']->set('vaultable.kdf.ops_limit', SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE);
        $app['config']->set('vaultable.kdf.mem_limit', SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);
        $app['config']->set('vaultable.session.timeout', 900);
        $app['config']->set('vaultable.recovery.enabled', false);
    }

    protected function getPackageProviders($app): array
    {
        return [
            ServiceProvider::class,
        ];
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }
}
