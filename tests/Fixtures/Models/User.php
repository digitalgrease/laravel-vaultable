<?php

namespace DigitalGrease\Vaultable\Tests\Fixtures\Models;

use DigitalGrease\Vaultable\Tests\Fixtures\Factories\UserFactory;
use DigitalGrease\Vaultable\Traits\HasVault;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

#[UseFactory(UserFactory::class)]
class User extends Authenticatable
{
    use HasFactory, HasVault, Notifiable;

    protected $guarded = [];
}
