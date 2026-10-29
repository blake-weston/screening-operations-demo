<?php

declare(strict_types=1);

// SR07: one boundary covers bootstrap, authentication, every database read and every write.
try {
    require __DIR__ . '/bootstrap.php';
    require_once __DIR__ . '/scan_events_repository.php';
    require_once __DIR__ . '/event_notes_repository.php';

    // SR01: authentication is required for reads and all mutations are POST plus session-bound CSRF.
    $user = require_auth();
    $source = $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET;
    $eventId = positive_integer($source['event_id'] ?? null);
    if ($eventId === null) {
        http_response_code(400);
        render_header('Invalid event');
        echo '<main class="card"><h1>Invalid event</h1><p>The event identifier must be a positive integer.</p></main>';
        render_footer();
        exit;
    }

    $event = fetch_accessible_event($user, $eventId);
    if ($event === null) {
        // SR05/SR07: do not disclose whether an inaccessible event exists.
        http_response_code(404);
        render_header('Event not found');
        echo '<main class="card"><h1>Event not found</h1><p>The event was not found or is not available to your account.</p></main>';
        render_footer();
        exit;
    }

    $errors = [];
    $editNote = null;
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!verify_csrf_token(is_string($_POST['csrf_token'] ?? null) ? $_POST['csrf_token'] : null)) {
            $errors[] = 'The request could not be verified. Refresh the page and try again.';
        } else {
            $action = is_string($_POST['action'] ?? null) ? $_POST['action'] : '';
            $noteId = positive_integer($_POST['note_id'] ?? null);

            if ($action === 'create') {
                [$text, $visibility, $errors] = validate_note_input($_POST['note_text'] ?? null, $_POST['visibility'] ?? null);
                if ($errors === []) {
                    create_event_note($eventId, (int) $user['id'], $text, $visibility);
                    flash('success', 'Note created.');
                    redirect('/notes.php?event_id=' . $eventId);
                }
            } elseif ($action === 'update' && $noteId !== null) {
                [$text, $visibility, $errors] = validate_note_input($_POST['note_text'] ?? null, $_POST['visibility'] ?? null);
                if ($errors === [] && !update_event_note($noteId, $eventId, (int) $user['id'], $text, $visibility)) {
                    $errors[] = 'The note was not found or you are not permitted to edit it.';
                } elseif ($errors === []) {
                    flash('success', 'Note updated.');
                    redirect('/notes.php?event_id=' . $eventId);
                }
                $editNote = ['id' => $noteId, 'note_text' => $text ?? '', 'visibility' => $visibility ?? 'private'];
            } elseif ($action === 'delete' && $noteId !== null) {
                if (!delete_event_note($noteId, $eventId, (int) $user['id'])) {
                    $errors[] = 'The note was not found or you are not permitted to delete it.';
                } else {
                    flash('success', 'Note deleted.');
                    redirect('/notes.php?event_id=' . $eventId);
                }
            } else {
                $errors[] = 'The note request was invalid.';
            }
        }
    } elseif (isset($_GET['edit'])) {
        $noteId = positive_integer($_GET['edit']);
        if ($noteId === null || ($editNote = fetch_owned_note_for_event($noteId, $eventId, (int) $user['id'])) === null) {
            $errors[] = 'The note was not found or you are not permitted to edit it.';
        }
    }

    $notes = fetch_visible_event_notes($user, $event);
} catch (Throwable $throwable) {
    // SR07: never log note content, credentials, tokens, exception messages or stack traces.
    error_log(sprintf(
        'Notes request failed: method=%s event=%s error=%s',
        $_SERVER['REQUEST_METHOD'] ?? 'unknown',
        isset($eventId) && is_int($eventId) ? (string) $eventId : 'unresolved',
        $throwable::class
    ));

    http_response_code(500);
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
    echo '<!doctype html><html lang="en"><head><meta charset="UTF-8"><title>Request unavailable</title></head>';
    echo '<body><main><h1>Request unavailable</h1><p>The note request could not be completed. Please try again.</p></main></body></html>';
    exit;
}

render_header('Event notes');
?>
<main>
  <section class="card card-compact event-header">
    <div class="event-header-content">
      <h1>Event <?= escape_html((string) $event['id']) ?> notes</h1>
      <div class="event-summary">
        <span><?= escape_html($event['scanner_location']) ?></span><span><?= escape_html($event['scan_time']) ?></span>
        <span class="<?= escape_html(risk_badge_class($event['risk_level'])) ?>"><?= escape_html($event['risk_level']) ?></span>
      </div>
    </div>
    <a class="button button-secondary" href="/index.php">Back to events</a>
  </section>
  <section class="card card-spaced">
    <h2><?= $editNote === null ? 'New note' : 'Edit note' ?></h2>
    <?php if ($errors !== []): ?><div class="flash flash-error"><?= escape_html(implode(' ', $errors)) ?></div><?php endif; ?>
    <form method="post" action="/notes.php">
      <input type="hidden" name="csrf_token" value="<?= escape_html(csrf_token()) ?>">
      <input type="hidden" name="event_id" value="<?= escape_html((string) $eventId) ?>">
      <input type="hidden" name="action" value="<?= $editNote === null ? 'create' : 'update' ?>">
      <?php if ($editNote !== null): ?><input type="hidden" name="note_id" value="<?= escape_html((string) $editNote['id']) ?>"><?php endif; ?>
      <label for="note_text">Plain-text note</label>
      <textarea id="note_text" name="note_text" maxlength="2000" required><?= escape_html((string) ($editNote['note_text'] ?? '')) ?></textarea>
      <label for="visibility">Visibility</label>
      <select id="visibility" name="visibility">
        <option value="private"<?= ($editNote['visibility'] ?? 'private') === 'private' ? ' selected' : '' ?>>Private</option>
        <option value="shared"<?= ($editNote['visibility'] ?? '') === 'shared' ? ' selected' : '' ?>>Shared</option>
      </select>
      <div class="actions"><button type="submit"><?= $editNote === null ? 'Add note' : 'Save changes' ?></button></div>
    </form>
  </section>
</main>
<section class="card card-spaced">
  <h2>Notes</h2>
  <?php if ($notes === []): ?><p class="muted">No notes are visible to you for this event.</p><?php endif; ?>
  <?php foreach ($notes as $note): ?>
    <article class="note">
      <div class="note-meta">
        <span>Author: <?= escape_html($note['author_name']) ?></span><span>Created: <?= escape_html($note['created_at']) ?></span>
        <span>Visibility: <?= escape_html($note['visibility']) ?></span>
        <?php if ($note['updated_at'] !== null): ?><span>Last edited: <?= escape_html($note['updated_at']) ?></span><?php endif; ?>
      </div>
      <!-- SR06: text is escaped at the HTML text context and is never inserted into script or CSS. -->
      <p class="note-text"><?= escape_html($note['note_text']) ?></p>
      <?php if (user_can_modify_event_note($user, $event, $note)): ?>
        <div class="actions actions-compact">
          <a class="button button-secondary" href="/notes.php?event_id=<?= escape_html((string) $eventId) ?>&amp;edit=<?= escape_html((string) $note['id']) ?>">Edit</a>
          <form class="inline-form" method="post" action="/notes.php">
            <input type="hidden" name="csrf_token" value="<?= escape_html(csrf_token()) ?>"><input type="hidden" name="event_id" value="<?= escape_html((string) $eventId) ?>">
            <input type="hidden" name="note_id" value="<?= escape_html((string) $note['id']) ?>"><input type="hidden" name="action" value="delete">
            <button class="button-danger" type="submit">Delete</button>
          </form>
        </div>
      <?php endif; ?>
    </article>
  <?php endforeach; ?>
</section>
<?php render_footer();
