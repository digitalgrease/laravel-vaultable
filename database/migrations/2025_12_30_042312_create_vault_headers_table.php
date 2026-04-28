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
        Schema::create('vault_headers', function (Blueprint $table) {
            $table->id();
            $table->string('vaultable_type');
            $table->unsignedBigInteger('vaultable_id');
            $table->tinyInteger('kdf_algorithm');
            $table->binary('kdf_salt', 16);
            $table->unsignedInteger('kdf_ops_limit');
            $table->unsignedBigInteger('kdf_mem_limit');
            $table->string('aead_algorithm');
            $table->binary('aead_nonce', 24);
            $table->binary('encrypted_vmk', 48);
            $table->unsignedInteger('version')->default(1);
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->unique(['vaultable_type', 'vaultable_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('vault_headers');
    }
};
