<?php

namespace DigitalGrease\Vaultable\Http\Middleware;

use Closure;
use DigitalGrease\Vaultable\Contracts\VaultServiceInterface;
use DigitalGrease\Vaultable\Exceptions\VaultLockedException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureVaultUnlocked
{
    public function __construct(
        protected VaultServiceInterface $vaultService,
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param Closure(Request): Response $next
     *
     * @throws VaultLockedException
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->vaultService->isUnlocked()) {
            if ($request->expectsJson()) {
                throw new VaultLockedException;
            }

            return redirect()->route('login');
        }

        return $next($request);
    }
}
