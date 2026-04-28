<?php

declare(strict_types=1);

namespace DigitalGrease\Vaultable;

use DigitalGrease\Vaultable\Actions\Fortify\CreateNewUserWithVault;
use DigitalGrease\Vaultable\Actions\Fortify\ResetUserPasswordWithVault;
use DigitalGrease\Vaultable\Actions\Fortify\TwoFactorAuthWithVault;
use DigitalGrease\Vaultable\Actions\Fortify\UnlockVaultOnLogin;
use DigitalGrease\Vaultable\Actions\Fortify\UpdateUserPasswordWithVault;
use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Crypto\AeadEncryption;
use DigitalGrease\Vaultable\Crypto\KeyDerivation;
use DigitalGrease\Vaultable\Http\Middleware\EnsureVaultUnlocked;
use DigitalGrease\Vaultable\Services\RecoveryKeyService;
use DigitalGrease\Vaultable\Services\VaultService;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Event;
use Laravel\Fortify\Actions\AttemptToAuthenticate;
use Laravel\Fortify\Actions\EnsureLoginIsNotThrottled;
use Laravel\Fortify\Actions\PrepareAuthenticatedSession;
use Laravel\Fortify\Contracts\CreatesNewUsers;
use Laravel\Fortify\Contracts\ResetsUserPasswords;
use Laravel\Fortify\Contracts\UpdatesUserPasswords;
use Laravel\Fortify\Features;
use Laravel\Fortify\Fortify;

class ServiceProvider extends \Illuminate\Support\ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/vaultable.php', 'vaultable');

        $this->registerCryptoServices();
        $this->registerVaultService();
        $this->registerRecoveryKeyService();
    }

    public function boot(): void
    {
        $this->validateSessionDriver();
        $this->publishAssets();
        $this->registerMorphMap();
        $this->registerMiddleware();
        $this->registerLogoutListener();

        if ($this->shouldIntegrateWithFortify()) {
            $this->registerFortifyIntegration();
        }
    }

    /**
     * Validate that a server-side session driver is being used.
     *
     * The split-key VMK storage requires the session to be stored server-side.
     * Using the 'cookie' driver would defeat the security model by placing
     * both the encrypted VMK and the session key on the client.
     *
     * @throws \RuntimeException
     */
    protected function validateSessionDriver(): void
    {
        $driver = $this->app['config']->get('session.driver');

        if ($driver === 'cookie') {
            throw new \RuntimeException(
                'Laravel Vaultable requires a server-side session driver (file, database, redis, etc.). '.
                'The "cookie" session driver stores all session data on the client, which defeats the '.
                'split-key security model. Please change SESSION_DRIVER in your .env file.'
            );
        }

        if ($driver === 'array' && ! $this->app->runningUnitTests()) {
            throw new \RuntimeException(
                'Laravel Vaultable requires a persistent session driver. '.
                'The "array" session driver does not persist data across requests.'
            );
        }
    }

    protected function registerCryptoServices(): void
    {
        $this->app->singleton(KeyDerivation::class, function ($app) {
            return new KeyDerivation(
                pepper: $app['config']->get('vaultable.pepper'),
            );
        });

        $this->app->singleton(AeadEncryption::class, function () {
            return new AeadEncryption;
        });
    }

    protected function registerVaultService(): void
    {
        $this->app->singleton(VaultServiceInterface::class, function ($app) {
            return new VaultService(
                keyDerivation: $app->make(KeyDerivation::class),
                aeadEncryption: $app->make(AeadEncryption::class),
                session: $app->make('session.store'),
                cookie: $app->make('cookie'),
                request: $app->make('request'),
                sessionTimeout: $app['config']->get('vaultable.session.timeout', 900),
                opsLimit: $app['config']->get('vaultable.kdf.ops_limit', SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE),
                memLimit: $app['config']->get('vaultable.kdf.mem_limit', SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE),
            );
        });

        $this->app->alias(VaultServiceInterface::class, VaultService::class);
    }

    protected function registerRecoveryKeyService(): void
    {
        $this->app->singleton(RecoveryKeyService::class, function ($app) {
            return new RecoveryKeyService(
                aeadEncryption: $app->make(AeadEncryption::class),
                keyDerivation: $app->make(KeyDerivation::class),
                opsLimit: $app['config']->get('vaultable.kdf.ops_limit', SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE),
                memLimit: $app['config']->get('vaultable.kdf.mem_limit', SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE),
            );
        });
    }

    protected function publishAssets(): void
    {
        $this->publishes([
            __DIR__.'/../config/vaultable.php' => config_path('vaultable.php'),
        ], 'vaultable-config');

        $this->publishes([
            __DIR__.'/../database/migrations/' => database_path('migrations'),
        ], 'vaultable-migrations');
    }

    protected function registerMorphMap(): void
    {
        $models = $this->app['config']->get('vaultable.models', []);

        if (! empty($models)) {
            Relation::morphMap($models);
        }
    }

    protected function registerMiddleware(): void
    {
        /** @var Router $router */
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('vault.unlocked', EnsureVaultUnlocked::class);
    }

    protected function registerLogoutListener(): void
    {
        Event::listen(Logout::class, function () {
            $this->app->make(VaultServiceInterface::class)->lockVault();
        });
    }

    protected function shouldIntegrateWithFortify(): bool
    {
        return $this->app['config']->get('vaultable.fortify.auto_integrate', true)
            && class_exists(Fortify::class);
    }

    protected function registerFortifyIntegration(): void
    {
        $this->extendFortifyContracts();
        $this->registerAuthenticationPipeline();
    }

    protected function extendFortifyContracts(): void
    {
        $recoveryEnabled = $this->app['config']->get('vaultable.recovery.enabled', false);

        $this->app->extend(CreatesNewUsers::class, function ($service, $app) use ($recoveryEnabled) {
            return new CreateNewUserWithVault(
                createNewUser: $service,
                vaultService: $app->make(VaultServiceInterface::class),
                recoveryKeyService: $app->make(RecoveryKeyService::class),
                recoveryEnabled: $recoveryEnabled,
            );
        });

        $this->app->extend(UpdatesUserPasswords::class, function ($service, $app) {
            return new UpdateUserPasswordWithVault(
                updatesUserPasswords: $service,
                vaultService: $app->make(VaultServiceInterface::class),
            );
        });

        $this->app->extend(ResetsUserPasswords::class, function ($service, $app) use ($recoveryEnabled) {
            return new ResetUserPasswordWithVault(
                resetsUserPasswords: $service,
                vaultService: $app->make(VaultServiceInterface::class),
                recoveryKeyService: $app->make(RecoveryKeyService::class),
                recoveryEnabled: $recoveryEnabled,
            );
        });
    }

    protected function registerAuthenticationPipeline(): void
    {
        $recoveryEnabled = $this->app['config']->get('vaultable.recovery.enabled', false);

        Fortify::authenticateThrough(function () use ($recoveryEnabled) {
            $pipeline = [
                $this->app['config']->get('fortify.limiters.login')
                    ? null
                    : EnsureLoginIsNotThrottled::class,
            ];

            if (Features::enabled(Features::twoFactorAuthentication())) {
                $pipeline[] = function ($app) use ($recoveryEnabled) {
                    return new TwoFactorAuthWithVault(
                        guard: $app->make(StatefulGuard::class),
                        vaultService: $app->make(VaultServiceInterface::class),
                        recoveryKeyService: $app->make(RecoveryKeyService::class),
                        recoveryEnabled: $recoveryEnabled,
                    );
                };
            }

            $pipeline[] = AttemptToAuthenticate::class;
            $pipeline[] = PrepareAuthenticatedSession::class;
            $pipeline[] = function ($app) use ($recoveryEnabled) {
                return new UnlockVaultOnLogin(
                    vaultService: $app->make(VaultServiceInterface::class),
                    recoveryKeyService: $app->make(RecoveryKeyService::class),
                    recoveryEnabled: $recoveryEnabled,
                );
            };

            return array_filter($pipeline);
        });
    }
}
