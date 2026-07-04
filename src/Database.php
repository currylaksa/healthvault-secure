<?php
declare(strict_types=1);

namespace HealthVault;

use PDO;

/**
 * Database — PDO connection factory.
 *
 * SECURITY DESIGN (Chapter 2 / Question 2):
 *   - Uses PDO with real prepared statements (emulation OFF) so the driver ships
 *     the SQL template and the bound data over SEPARATE channels. User input can
 *     never cross the data-plane / command-plane boundary -> SQL Injection
 *     (Hidden Flaw A) is structurally impossible, not merely filtered.
 *   - Credentials come from the runtime environment (.env), not source code.
 *   - The connection SHOULD use a least-privilege DB account (SELECT-only for the
 *     search proxy), NOT root — the legacy note admitted root access, which turned
 *     one SQLi into a full-database compromise.
 */
final class Database
{
    public static function connect(): PDO
    {
        $host = $_ENV['DB_HOST'] ?? '127.0.0.1';
        $port = $_ENV['DB_PORT'] ?? '3306';
        $name = $_ENV['DB_NAME'] ?? 'medic_vault_db';
        $user = $_ENV['DB_USER'] ?? '';
        $pass = $_ENV['DB_PASS'] ?? '';

        $dsn = "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4";

        return new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false, // force native prepared statements
        ]);
    }
}
