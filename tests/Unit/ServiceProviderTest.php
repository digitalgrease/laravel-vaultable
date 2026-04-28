<?php

namespace DigitalGrease\Vaultable\Tests\Unit;

use DigitalGrease\Vaultable\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class ServiceProviderTest extends TestCase
{
    #[Test]
    public function it_throws_exception_when_cookie_session_driver_is_used(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('server-side session driver');

        config()->set('session.driver', 'cookie');

        // Re-boot the service provider to trigger validation
        $provider = new \DigitalGrease\Vaultable\ServiceProvider($this->app);
        $provider->boot();
    }

    #[Test]
    public function it_allows_file_session_driver(): void
    {
        config()->set('session.driver', 'file');

        $provider = new \DigitalGrease\Vaultable\ServiceProvider($this->app);
        $provider->boot();

        $this->assertTrue(true); // No exception thrown
    }

    #[Test]
    public function it_allows_database_session_driver(): void
    {
        config()->set('session.driver', 'database');

        $provider = new \DigitalGrease\Vaultable\ServiceProvider($this->app);
        $provider->boot();

        $this->assertTrue(true);
    }

    #[Test]
    public function it_allows_redis_session_driver(): void
    {
        config()->set('session.driver', 'redis');

        $provider = new \DigitalGrease\Vaultable\ServiceProvider($this->app);
        $provider->boot();

        $this->assertTrue(true);
    }

    #[Test]
    public function it_allows_array_session_driver_in_tests(): void
    {
        config()->set('session.driver', 'array');

        $provider = new \DigitalGrease\Vaultable\ServiceProvider($this->app);
        $provider->boot();

        $this->assertTrue(true);
    }
}
