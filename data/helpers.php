<?php

declare(strict_types=1);

function e(string $value): string
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
  <title><?= e($title) ?> | <?= e($config['app_name']) ?></title>
  <link rel="icon" type="image/png" href="/favicon.png">
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f1ea;
      --panel: #fffdf8;
      --text: #1f2933;
      --muted: #52606d;
      --accent: #0f4c5c;
      --danger: #9b2226;
      --success: #2d6a4f;
      --warning: #9c5c00;
      --border: #d9d0c2;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(15, 76, 92, 0.12), transparent 35%),
        linear-gradient(180deg, #f8f6f0 0%, var(--bg) 100%);
      color: var(--text);
      min-height: 100vh;
    }
    .shell {
      max-width: 1080px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }
    .nav {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 24px;
    }
    .nav a {
      color: var(--accent);
      text-decoration: none;
      font-weight: 700;
    }
    .nav-links {
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
    }
    .nav-user {
      color: var(--muted);
      font-size: 0.95rem;
    }
    .nav-logout {
      background: none;
      border: none;
      color: var(--accent);
      font: inherit;
      font-weight: 700;
      padding: 0;
      cursor: pointer;
    }
    .nav-form {
      margin: 0;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 28px;
      box-shadow: 0 18px 40px rgba(31, 41, 51, 0.08);
    }
    h1, h2 { margin-top: 0; }
    p { line-height: 1.6; }
    .muted { color: var(--muted); }
    .flash {
      border-radius: 12px;
      padding: 14px 16px;
      margin-bottom: 20px;
      font-weight: 700;
    }
    .flash-success { background: rgba(45, 106, 79, 0.12); color: var(--success); }
    .flash-error { background: rgba(155, 34, 38, 0.12); color: var(--danger); }
    label {
      display: block;
      margin-bottom: 6px;
      font-weight: 700;
    }
    input, select {
      width: 100%;
      padding: 12px 14px;
      border-radius: 10px;
      border: 1px solid var(--border);
      margin-bottom: 16px;
      font: inherit;
      background: #fff;
    }
    .button, button {
      display: inline-block;
      border: 0;
      border-radius: 999px;
      background: var(--accent);
      color: #fff;
      padding: 12px 18px;
      font: inherit;
      font-weight: 700;
      text-decoration: none;
      cursor: pointer;
    }
    .button-secondary {
      background: transparent;
      color: var(--accent);
      border: 1px solid var(--accent);
    }
    .actions {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 20px;
    }
    .form-narrow {
      max-width: 420px;
      margin: 0 auto;
    }
    .form-actions-right {
      display: flex;
      justify-content: flex-end;
      margin-top: 8px;
    }
    .grid {
      display: grid;
      gap: 20px;
    }
    .grid-three {
      display: grid;
      gap: 16px;
    }
    @media (min-width: 720px) {
      .grid {
        grid-template-columns: 1.6fr 1fr;
      }
      .grid-three {
        grid-template-columns: repeat(3, 1fr);
      }
    }
    .code {
      font-family: "Courier New", monospace;
      background: #f3eee4;
      border-radius: 6px;
      padding: 2px 6px;
    }
    .metric {
      background: #f8f4eb;
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 16px;
    }
    .metric-value {
      display: block;
      font-size: 1.8rem;
      font-weight: 700;
      margin-top: 4px;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 0.9rem;
      font-weight: 700;
    }
    .badge-low {
      background: rgba(45, 106, 79, 0.14);
      color: var(--success);
    }
    .badge-medium {
      background: rgba(214, 140, 32, 0.16);
      color: var(--warning);
    }
    .badge-high {
      background: rgba(155, 34, 38, 0.14);
      color: var(--danger);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
    }
    .thumb-link {
      display: inline-block;
      padding: 0;
      border: 0;
      background: transparent;
      text-decoration: none;
      cursor: pointer;
    }
    .thumb-image {
      display: block;
      width: 110px;
      height: 80px;
      object-fit: cover;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: #f3eee4;
    }
    .thumb-placeholder {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 110px;
      height: 80px;
      border-radius: 10px;
      border: 1px dashed var(--border);
      color: var(--muted);
      font-size: 0.85rem;
      text-align: center;
      background: #f8f4eb;
    }
    .image-modal[hidden] {
      display: none;
    }
    .image-modal {
      position: fixed;
      inset: 0;
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      background: rgba(31, 41, 51, 0.72);
    }
    .image-modal-dialog {
      position: relative;
      width: min(92vw, 960px);
      max-height: 92vh;
      padding: 18px 18px 14px;
      border: 1px solid rgba(217, 208, 194, 0.9);
      border-radius: 18px;
      background: var(--panel);
      box-shadow: 0 24px 56px rgba(31, 41, 51, 0.28);
    }
    .image-modal-close {
      position: absolute;
      top: 10px;
      right: 10px;
      width: 40px;
      height: 40px;
      padding: 0;
      border-radius: 999px;
      font-size: 1.4rem;
      line-height: 1;
    }
    .image-modal-figure {
      margin: 0;
      padding-top: 22px;
    }
    .image-modal-full {
      display: block;
      width: 100%;
      max-height: calc(92vh - 90px);
      object-fit: contain;
      border-radius: 12px;
      background: #f3eee4;
    }
    .image-modal-caption {
      margin-top: 10px;
      color: var(--muted);
      font-size: 0.95rem;
      text-align: center;
    }
    th, td {
      padding: 12px 10px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-size: 0.95rem;
      letter-spacing: 0.02em;
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="nav">
      <a href="/index.php"><?= e($config['app_name']) ?></a>
      <div class="nav-links">
        <?php if ($user !== null): ?>
          <a href="/index.php">Scan Events</a>
          <?php if ($user['role'] === 'admin'): ?>
            <a href="/operators.php">Security Administrator</a>
          <?php endif; ?>
          <span class="nav-user"><?= e($user['display_name']) ?> (<?= e($user['role']) ?>)</span>
          <form class="nav-form" method="post" action="/logout.php">
            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
            <button class="nav-logout" type="submit">Logout</button>
          </form>
        <?php else: ?>
          <a href="/login.php">Login</a>
        <?php endif; ?>
      </div>
    </div>
    <?php if ($flash !== null): ?>
      <div class="flash flash-<?= e($flash['type']) ?>"><?= e($flash['message']) ?></div>
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
