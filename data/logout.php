<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !verify_csrf_token($_POST['csrf_token'] ?? null)) {
    http_response_code(405);
    render_header('Request blocked');
    ?>
    <main class="card">
      <h1>Request blocked</h1>
      <p class="muted">Logout requires a valid form submission token.</p>
      <div class="actions">
        <a class="button" href="/index.php">Return home</a>
      </div>
    </main>
    <?php
    render_footer();
    exit;
}

destroy_session_state();
session_start();
session_regenerate_id(true);
flash('success', 'You have been signed out.');
redirect('/login.php');
