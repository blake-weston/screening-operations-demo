<?php

declare(strict_types=1);

require_once __DIR__ . '/note_policy.php';

// SR04: IDs are accepted only as scalar, canonical positive decimal integers.
function positive_integer(mixed $value): ?int
{
    if (!is_string($value) && !is_int($value)) {
        return null;
    }

    $stringValue = (string) $value;
    if (!preg_match('/^[1-9][0-9]*$/D', $stringValue)) {
        return null;
    }

    $integerValue = filter_var($stringValue, FILTER_VALIDATE_INT);
    return $integerValue === false ? null : $integerValue;
}

// SR02: enforce the 1-2,000 character application bound.
// SR03: normalise line endings and reject characters outside printable ASCII plus LF.
// SR04: default omitted visibility to private; reject supplied unsupported values and structures.
function validate_note_input(mixed $text, mixed $visibility): array
{
    $errors = [];
    if (!is_string($text)) {
        return [null, null, ['Note must be a text value.']];
    }

    $validatedVisibility = $visibility === null ? 'private' : $visibility;
    if (!is_string($validatedVisibility) || !in_array($validatedVisibility, ['private', 'shared'], true)) {
        $errors[] = 'Visibility must be private or shared.';
    }

    $normalised = str_replace(["\r\n", "\r"], "\n", $text);
    if (!preg_match('/^[\x20-\x7E\n]*$/D', $normalised)) {
        $errors[] = 'Note text may contain printable ASCII characters and line breaks only.';
    }

    $normalised = trim($normalised, " \n");
    $length = strlen($normalised);
    if ($length < 1 || $length > 2000) {
        $errors[] = 'Note text must contain between 1 and 2,000 characters.';
    }

    return [$normalised, is_string($validatedVisibility) ? $validatedVisibility : null, $errors];
}

// SR05: every operation first resolves the event and applies the current lane access rule.
function fetch_accessible_event(array $user, int $eventId): ?array
{
    $statement = db()->prepare(
        'SELECT id, scan_time, terminal_name, lane_number, scanner_location, risk_level, threat_category
         FROM scan_events WHERE id = :id LIMIT 1'
    );
    $statement->execute(['id' => $eventId]);
    $event = $statement->fetch();

    return $event && user_can_access_scan_event($user, $event) ? $event : null;
}

// FR03-FR04, SR05-SR06: SQL enforces visibility and returns only display-safe source text.
function fetch_visible_event_notes(array $user, array $event): array
{
    $statement = db()->prepare(
        'SELECT n.id, n.note_text, n.visibility, n.created_at, n.updated_at,
                n.author_operator_id, o.display_name AS author_name
         FROM event_notes n
         JOIN operators o ON o.id = n.author_operator_id
         WHERE n.scan_event_id = :event_id
           AND (n.visibility = \'shared\' OR n.author_operator_id = :operator_id)
         ORDER BY n.created_at DESC, n.id DESC'
    );
    $statement->execute(['event_id' => (int) $event['id'], 'operator_id' => (int) $user['id']]);

    // SR05: retain the restrictive SQL predicate and apply the centralized policy as defence in depth.
    return array_values(array_filter(
        $statement->fetchAll(),
        static fn (array $note): bool => user_can_view_event_note($user, $event, $note)
    ));
}

// FR04/SR05: build the event boundary used by the cross-event note summary.
// Lane users are restricted in SQL; managers and administrators may access every event.
function build_event_note_summary_scope(array $user, ?int $eventId = null): array
{
    $clauses = [];
    $parameters = [];

    if ($eventId !== null) {
        $clauses[] = 'e.id = :filter_event_id';
        $parameters['filter_event_id'] = $eventId;
    }

    if ($user['role'] === 'lane') {
        $assignments = $user['lane_assignments'];
        if ($assignments === []) {
            $clauses[] = '1 = 0';
        } else {
            $assignmentClauses = [];
            foreach ($assignments as $index => $assignment) {
                $terminalKey = 'note_terminal_' . $index;
                $laneKey = 'note_lane_' . $index;
                $assignmentClauses[] = "(e.terminal_name = :{$terminalKey} AND e.lane_number = :{$laneKey})";
                $parameters[$terminalKey] = $assignment['terminal_name'];
                $parameters[$laneKey] = (int) $assignment['lane_number'];
            }
            $clauses[] = '(' . implode(' OR ', $assignmentClauses) . ')';
        }
    }

    return [$clauses, $parameters];
}

// FR04/SR05: supply only events the current user can select as a summary filter.
function fetch_accessible_event_note_options(array $user): array
{
    [$clauses, $parameters] = build_event_note_summary_scope($user);
    $query = 'SELECT e.id, e.scan_time, e.terminal_name, e.lane_number, e.scanner_location
              FROM scan_events e';
    if ($clauses !== []) {
        $query .= ' WHERE ' . implode(' AND ', $clauses);
    }
    $query .= ' ORDER BY e.scan_time DESC, e.id DESC';

    $statement = db()->prepare($query);
    $statement->execute($parameters);
    return $statement->fetchAll();
}

// FR04/SR05-SR06: list all notes visible to the user, with their event context.
function fetch_visible_event_note_summary(array $user, ?int $eventId = null): array
{
    [$scopeClauses, $parameters] = build_event_note_summary_scope($user, $eventId);
    $clauses = ["(n.visibility = 'shared' OR n.author_operator_id = :operator_id)"];
    $parameters['operator_id'] = (int) $user['id'];
    array_push($clauses, ...$scopeClauses);

    $statement = db()->prepare(
        'SELECT n.id, n.note_text, n.visibility, n.created_at, n.updated_at,
                n.author_operator_id, o.display_name AS author_name,
                e.id AS event_id, e.scan_time, e.terminal_name, e.lane_number,
                e.scanner_location, e.risk_level, e.threat_category
         FROM event_notes n
         JOIN operators o ON o.id = n.author_operator_id
         JOIN scan_events e ON e.id = n.scan_event_id
         WHERE ' . implode(' AND ', $clauses) . '
         ORDER BY n.created_at DESC, n.id DESC'
    );
    $statement->execute($parameters);
    $notes = $statement->fetchAll();

    // Retain the central policy check as defence in depth after the SQL boundary.
    return array_values(array_filter(
        $notes,
        static fn (array $note): bool => user_can_view_event_note($user, $note, $note)
    ));
}

function fetch_owned_note_for_event(int $noteId, int $eventId, int $operatorId): ?array
{
    $statement = db()->prepare(
        'SELECT id, scan_event_id, author_operator_id, note_text, visibility, created_at, updated_at
         FROM event_notes
         WHERE id = :id AND scan_event_id = :event_id AND author_operator_id = :operator_id
         LIMIT 1'
    );
    $statement->execute(['id' => $noteId, 'event_id' => $eventId, 'operator_id' => $operatorId]);
    return $statement->fetch() ?: null;
}

// FR01-FR02, FR06, SR06: server-owned author/time fields and a parameterised write.
function create_event_note(int $eventId, int $operatorId, string $text, string $visibility): void
{
    $statement = db()->prepare(
        'INSERT INTO event_notes (scan_event_id, author_operator_id, note_text, visibility)
         VALUES (:event_id, :operator_id, :note_text, :visibility)'
    );
    $statement->execute([
        'event_id' => $eventId,
        'operator_id' => $operatorId,
        'note_text' => $text,
        'visibility' => $visibility,
    ]);
}

// FR05, SR05-SR07: ownership is repeated in the atomic UPDATE and the edit time is server-owned.
function update_event_note(int $noteId, int $eventId, int $operatorId, string $text, string $visibility): bool
{
    $statement = db()->prepare(
        'UPDATE event_notes SET note_text = :note_text, visibility = :visibility, updated_at = CURRENT_TIMESTAMP
         WHERE id = :id AND scan_event_id = :event_id AND author_operator_id = :operator_id'
    );
    $statement->execute([
        'id' => $noteId, 'event_id' => $eventId, 'operator_id' => $operatorId,
        'note_text' => $text, 'visibility' => $visibility,
    ]);
    return $statement->rowCount() === 1;
}

// FR05, SR05-SR07: delete is parameterised and constrained by event and author in one statement.
function delete_event_note(int $noteId, int $eventId, int $operatorId): bool
{
    $statement = db()->prepare(
        'DELETE FROM event_notes WHERE id = :id AND scan_event_id = :event_id AND author_operator_id = :operator_id'
    );
    $statement->execute(['id' => $noteId, 'event_id' => $eventId, 'operator_id' => $operatorId]);
    return $statement->rowCount() === 1;
}
