<?php

declare(strict_types=1);

function escape_html(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function verify_csrf_token(?string $token): bool
{
    return is_string($token)
        && isset($_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $token);
}

function flash(string $type, string $message): void
{
    $_SESSION['flash'] = [
        'type' => $type,
        'message' => $message,
    ];
}

function get_flash(): ?array
{
    if (!isset($_SESSION['flash'])) {
        return null;
    }

    $flash = $_SESSION['flash'];
    unset($_SESSION['flash']);

    return $flash;
}

function redirect(string $path): never
{
    header('Location: ' . $path);
    exit;
}

function client_ip_address(): string
{
    $candidates = [
        $_SERVER['HTTP_X_REAL_IP'] ?? null,
        $_SERVER['REMOTE_ADDR'] ?? null,
    ];

    foreach ($candidates as $candidate) {
        if (is_string($candidate) && filter_var($candidate, FILTER_VALIDATE_IP)) {
            return $candidate;
        }
    }

    return 'unknown';
}

function login_throttle_key(string $identity, string $ipAddress): string
{
    return hash('sha256', strtolower(trim($identity)) . '|' . $ipAddress);
}

function login_lockout_status(string $identity, string $ipAddress): array
{
    $statement = db()->prepare(
        'SELECT failed_attempts, locked_until
         FROM login_throttles
         WHERE throttle_key = :throttle_key
         LIMIT 1'
    );
    $statement->execute([
        'throttle_key' => login_throttle_key($identity, $ipAddress),
    ]);
    $record = $statement->fetch();

    if (!$record) {
        return [
            'locked' => false,
            'seconds_remaining' => 0,
        ];
    }

    $lockedUntil = $record['locked_until'];
    if (!is_string($lockedUntil) || $lockedUntil === '') {
        return [
            'locked' => false,
            'seconds_remaining' => 0,
        ];
    }

    $lockedUntilTimestamp = strtotime($lockedUntil);
    if ($lockedUntilTimestamp === false || $lockedUntilTimestamp <= time()) {
        return [
            'locked' => false,
            'seconds_remaining' => 0,
        ];
    }

    return [
        'locked' => true,
        'seconds_remaining' => max(1, $lockedUntilTimestamp - time()),
    ];
}

function record_failed_login_attempt(string $identity, string $ipAddress): void
{
    $throttleKey = login_throttle_key($identity, $ipAddress);
    $now = time();
    $nowFormatted = date('Y-m-d H:i:s', $now);

    $statement = db()->prepare(
        'SELECT failed_attempts, locked_until
         FROM login_throttles
         WHERE throttle_key = :throttle_key
         LIMIT 1'
    );
    $statement->execute(['throttle_key' => $throttleKey]);
    $record = $statement->fetch();

    $failedAttempts = $record ? ((int) $record['failed_attempts'] + 1) : 1;
    $lockedUntil = $failedAttempts >= 5 ? date('Y-m-d H:i:s', $now + 900) : null;

    $upsert = db()->prepare(
        'INSERT INTO login_throttles (throttle_key, failed_attempts, last_failed_at, locked_until)
         VALUES (:throttle_key, :failed_attempts, :last_failed_at, :locked_until)
         ON DUPLICATE KEY UPDATE
           failed_attempts = VALUES(failed_attempts),
           last_failed_at = VALUES(last_failed_at),
           locked_until = VALUES(locked_until)'
    );
    $upsert->execute([
        'throttle_key' => $throttleKey,
        'failed_attempts' => $failedAttempts,
        'last_failed_at' => $nowFormatted,
        'locked_until' => $lockedUntil,
    ]);
}

function clear_login_throttle(string $identity, string $ipAddress): void
{
    $statement = db()->prepare(
        'DELETE FROM login_throttles
         WHERE throttle_key = :throttle_key'
    );
    $statement->execute([
        'throttle_key' => login_throttle_key($identity, $ipAddress),
    ]);
}

function destroy_session_state(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], (bool) $params['secure'], (bool) $params['httponly']);
    }

    session_destroy();
}

function enforce_session_idle_timeout(int $timeoutSeconds = 600): void
{
    if (empty($_SESSION['operator_id'])) {
        return;
    }

    $now = time();
    $lastActivityAt = isset($_SESSION['last_activity_at']) ? (int) $_SESSION['last_activity_at'] : $now;

    if (($now - $lastActivityAt) > $timeoutSeconds) {
        destroy_session_state();
        session_start();
        session_regenerate_id(true);
        flash('error', 'Your session expired after 10 minutes of inactivity. Please sign in again.');
        redirect('/login.php');
    }

    $_SESSION['last_activity_at'] = $now;
}

function current_user(): ?array
{
    if (empty($_SESSION['operator_id'])) {
        return null;
    }

    $statement = db()->prepare(
        'SELECT id, username, display_name, role, is_active
         FROM operators
         WHERE id = :id
         LIMIT 1'
    );
    $statement->execute(['id' => (int) $_SESSION['operator_id']]);
    $user = $statement->fetch();

    if (!$user || !(bool) $user['is_active']) {
        unset($_SESSION['operator_id']);
        return null;
    }

    $assignmentStatement = db()->prepare(
        'SELECT terminal_name, lane_number
         FROM operator_lane_assignments
         WHERE operator_id = :operator_id
         ORDER BY terminal_name, lane_number'
    );
    $assignmentStatement->execute(['operator_id' => (int) $user['id']]);
    $user['lane_assignments'] = $assignmentStatement->fetchAll();

    return $user;
}

function require_auth(): array
{
    $user = current_user();

    if ($user === null) {
        flash('error', 'Please sign in to access the scan event dashboard.');
        redirect('/login.php');
    }

    return $user;
}

function require_admin(): array
{
    $user = require_auth();

    if ($user['role'] !== 'admin') {
        flash('error', 'Administrator access is required for that screen.');
        redirect('/index.php');
    }

    return $user;
}

function require_guest(): void
{
    if (current_user() !== null) {
        redirect('/index.php');
    }
}

function render_header(string $title): void
{
    global $config;
    $flash = get_flash();
    $user = current_user();
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= escape_html($title) ?> | <?= escape_html($config['app_name']) ?></title>
  <link rel="icon" type="image/png" href="/favicon.png">
  <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
  <!-- SR11: stylesheet is external so style-src can exclude unsafe-inline. -->
  <link rel="stylesheet" href="/app.css">
</head>
<body>
  <div class="shell">
    <div class="nav">
      <a href="/index.php"><?= escape_html($config['app_name']) ?></a>
      <div class="nav-links">
        <?php if ($user !== null): ?>
          <a href="/index.php">Scan Events</a>
          <a href="/event_notes.php">Event Notes</a>
          <?php if ($user['role'] === 'admin'): ?>
            <a href="/operators.php">Security Administrator</a>
          <?php endif; ?>
          <span class="nav-user"><?= escape_html($user['display_name']) ?> (<?= escape_html($user['role']) ?>)</span>
          <form class="nav-form" method="post" action="/logout.php">
            <input type="hidden" name="csrf_token" value="<?= escape_html(csrf_token()) ?>">
            <button class="nav-logout" type="submit">Logout</button>
          </form>
        <?php else: ?>
          <a href="/login.php">Login</a>
        <?php endif; ?>
      </div>
    </div>
    <?php if ($flash !== null): ?>
      <div class="flash flash-<?= escape_html($flash['type']) ?>"><?= escape_html($flash['message']) ?></div>
    <?php endif; ?>
<?php
}

function render_footer(): void
{
    ?>
  </div>
</body>
</html>
<?php
}
