<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('vault_recovery_keys', function (Blueprint $table) {
            $table->id();
            $table->foreignId('vault_header_id')->constrained()->cascadeOnDelete();
            $table->binary('aead_nonce', 24);
            $table->binary('encrypted_vmk', 48);
            $table->string('recovery_key_hash');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('vault_recovery_keys');
    }
};
