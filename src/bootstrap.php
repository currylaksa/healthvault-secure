<?php
declare(strict_types=1);

/**
 * bootstrap.php — shared runtime initialization.
 * Loads Composer autoloader and the .env environment file so secrets
 * (DB credentials, APP_KEY) are injected at runtime rather than hardcoded.
 */

require_once __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(dirname(__DIR__));
$dotenv->load();

// Fail fast if required secrets are absent from the environment.
$dotenv->required(['APP_KEY', 'DB_HOST', 'DB_NAME', 'DB_USER'])->notEmpty();
