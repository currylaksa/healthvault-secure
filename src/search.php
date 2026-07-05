<?php
declare(strict_types=1);

/**
 * search.php (REFACTORED) — Patient & Medical Record Search Proxy.
 *
 * FIXES:
 *   Hidden Flaw A (SQL Injection) -> PDO prepared statement, bound parameter.
 *   Hidden Flaw B & C (Reflected XSS) -> htmlspecialchars() output encoding.
 *
 * -------------------- BEFORE (vulnerable) --------------------
 *   $keyword = $_GET['keyword'];
 *   $sql = "SELECT ... WHERE name LIKE '%" . $keyword . "%'"; // data crosses
 *   $result = $conn->query($sql);                             // into command plane
 *   echo "Result found for keyword: " . $keyword;            // raw reflection
 * -------------------------------------------------------------
 */

require_once __DIR__ . '/bootstrap.php';

use HealthVault\Database;

header('Content-Type: text/html; charset=utf-8');

$keyword = $_GET['keyword'] ?? '';

$pdo = Database::connect();

// DATA/COMMAND SEPARATION: the SQL template is fixed and compiled first; the
// user value travels as a bound parameter and is never parsed as SQL syntax.
$stmt = $pdo->prepare(
    'SELECT id, name, illness_history
       FROM patient_records
      WHERE name LIKE :kw'
);
// The % delimiters are concatenated into the BOUND VALUE, not the SQL text, so
// the user input can never alter the query structure (SQLi is still impossible).
// A user-typed % or _ remains a LIKE wildcard; add an ESCAPE clause only if
// literal-character matching is required.
$stmt->bindValue(':kw', '%' . $keyword . '%', PDO::PARAM_STR);
$stmt->execute();

$rows = $stmt->fetchAll();

// CONTEXT-AWARE OUTPUT ENCODING: every value entering the HTML body is encoded
// at the point of output. Encoding (not blacklist "sanitization") is what
// neutralizes XSS, because it is aware of the HTML output context.
$enc = static fn (string $v): string =>
    htmlspecialchars($v, ENT_QUOTES | ENT_HTML5, 'UTF-8');

if (count($rows) > 0) {
    foreach ($rows as $row) {
        echo '<div>Result found for keyword: ' . $enc($keyword) . '<br>';
        echo 'Patient: ' . $enc($row['name'])
           . ' | History: ' . $enc($row['illness_history'])
           . '</div><hr>';
    }
} else {
    echo 'No records found for: ' . $enc($keyword);
}
