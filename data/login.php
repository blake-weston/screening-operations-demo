<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

require_guest();

$errors = [];
$identity = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $identity = trim((string) ($_POST['identity'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $ipAddress = client_ip_address();

    if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {
        $errors[] = 'The request could not be verified. Refresh the page and try again.';
    }

    if ($identity === '' || $password === '') {
        $errors[] = 'Enter both your username and password.';
    }

    if ($errors === []) {
        $lockoutStatus = login_lockout_status($identity, $ipAddress);
        if ($lockoutStatus['locked']) {
            $errors[] = 'Too many failed sign-in attempts. Try again in ' . (string) $lockoutStatus['seconds_remaining'] . ' seconds.';
        }
    }

    if ($errors === []) {
        $statement = db()->prepare(
            'SELECT id, username, display_name, password_hash, role, is_active
             FROM operators
             WHERE username = :username
             LIMIT 1'
        );
        $statement->execute(['username' => $identity]);
        $user = $statement->fetch();

        if (!$user || !(bool) $user['is_active'] || !password_verify($password, $user['password_hash'])) {
            record_failed_login_attempt($identity, $ipAddress);
            $errors[] = 'Invalid credentials.';
        } else {
            clear_login_throttle($identity, $ipAddress);
            session_regenerate_id(true);
            $_SESSION['operator_id'] = (int) $user['id'];
            $_SESSION['last_activity_at'] = time();
            flash('success', 'You are now signed in.');
            redirect('/index.php');
        }
    }
}

render_header('Login');
?>
<main class="card">
  <h1>Operator sign in</h1>
  <?php if ($errors !== []): ?>
    <div class="flash flash-error"><?= e(implode(' ', $errors)) ?></div>
  <?php endif; ?>
  <form class="form-narrow" method="post" action="/login.php" novalidate>
    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

    <label for="identity">Username</label>
    <input
      id="identity"
      name="identity"
      type="text"
      required
      autocomplete="username"
      value="<?= e($identity) ?>"
    >

    <label for="password">Password</label>
    <input
      id="password"
      name="password"
      type="password"
      required
      autocomplete="current-password"
    >

    <div class="form-actions-right">
      <button type="submit">Sign in</button>
    </div>
  </form>
</main>
<?php
render_footer();
