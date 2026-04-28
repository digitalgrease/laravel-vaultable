<?php

namespace DigitalGrease\Vaultable\Tests\Fixtures\Factories;

use DigitalGrease\Vaultable\Tests\Fixtures\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

class UserFactory extends Factory
{
    protected $model = User::class;

    public function definition(): array
    {
        return [
            'name' => fake()->name(),
            'email' => fake()->safeEmail(),
            'password' => bcrypt('password'),
        ];
    }
}
