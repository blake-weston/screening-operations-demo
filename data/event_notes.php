<?php

declare(strict_types=1);

try {
    require __DIR__ . '/bootstrap.php';
    require_once __DIR__ . '/scan_events_repository.php';
    require_once __DIR__ . '/event_notes_repository.php';

    $user = require_auth();
    $selectedEventId = null;
    if (array_key_exists('event_id', $_GET) && $_GET['event_id'] !== '') {
        $selectedEventId = positive_integer($_GET['event_id']);
        if ($selectedEventId === null) {
            http_response_code(400);
            render_header('Invalid event filter');
            echo '<main class="card"><h1>Invalid event filter</h1><p>The event identifier must be a positive integer.</p></main>';
            render_footer();
            exit;
        }
    }

    $eventOptions = fetch_accessible_event_note_options($user);
    if ($selectedEventId !== null) {
        $selectedEventIsAccessible = array_filter(
            $eventOptions,
            static fn (array $event): bool => (int) $event['id'] === $selectedEventId
        ) !== [];
        if (!$selectedEventIsAccessible) {
            http_response_code(404);
            render_header('Event not found');
            echo '<main class="card"><h1>Event not found</h1><p>The event was not found or is not available to your account.</p></main>';
            render_footer();
            exit;
        }
    }

    $notes = fetch_visible_event_note_summary($user, $selectedEventId);
} catch (Throwable $throwable) {
    error_log(sprintf(
        'Event Notes summary failed: event=%s error=%s',
        isset($selectedEventId) && is_int($selectedEventId) ? (string) $selectedEventId : 'unresolved',
        $throwable::class
    ));
    http_response_code(500);
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
    echo '<!doctype html><html lang="en"><head><meta charset="UTF-8"><title>Request unavailable</title></head>';
    echo '<body><main><h1>Request unavailable</h1><p>The note history could not be loaded. Please try again.</p></main></body></html>';
    exit;
}

render_header('Event Notes');
?>
<main class="grid">
  <section class="card">
    <h1>Event Notes</h1>
    <p class="muted">All private notes you authored and shared notes for events you can currently access.</p>
  </section>
  <section class="card">
    <h2>Filter notes</h2>
    <form method="get" action="/event_notes.php">
      <label for="event_id">Event</label>
      <select id="event_id" name="event_id">
        <option value="">All accessible events</option>
        <?php foreach ($eventOptions as $event): ?>
          <option value="<?= escape_html((string) $event['id']) ?>"<?= $selectedEventId === (int) $event['id'] ? ' selected' : '' ?>>
            Event <?= escape_html((string) $event['id']) ?> — <?= escape_html($event['scanner_location']) ?> — <?= escape_html($event['scan_time']) ?>
          </option>
        <?php endforeach; ?>
      </select>
      <div class="actions">
        <button type="submit">Apply filter</button>
        <a class="button button-secondary" href="/event_notes.php">Clear</a>
      </div>
    </form>
  </section>
</main>

<section class="card card-spaced">
  <h2><?= $selectedEventId === null ? 'All visible notes' : 'Notes for event ' . escape_html((string) $selectedEventId) ?></h2>
  <?php if ($notes === []): ?>
    <p class="muted">No notes are visible for the selected event range.</p>
  <?php endif; ?>
  <?php foreach ($notes as $note): ?>
    <article class="note">
      <div class="note-meta">
        <strong><a href="/notes.php?event_id=<?= escape_html((string) $note['event_id']) ?>">Event <?= escape_html((string) $note['event_id']) ?></a></strong>
        <span><?= escape_html($note['scanner_location']) ?></span>
        <span>Scanned: <?= escape_html($note['scan_time']) ?></span>
        <span>Author: <?= escape_html($note['author_name']) ?></span>
        <span>Created: <?= escape_html($note['created_at']) ?></span>
        <span>Visibility: <?= escape_html($note['visibility']) ?></span>
        <?php if ($note['updated_at'] !== null): ?><span>Last edited: <?= escape_html($note['updated_at']) ?></span><?php endif; ?>
      </div>
      <p class="note-text"><?= escape_html($note['note_text']) ?></p>
      <div class="actions actions-compact">
        <a class="button button-secondary" href="/notes.php?event_id=<?= escape_html((string) $note['event_id']) ?>">Open event notes</a>
      </div>
    </article>
  <?php endforeach; ?>
</section>
<?php render_footer();
