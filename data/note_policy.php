<?php

declare(strict_types=1);

// SR05: note visibility never overrides the user's current access to the associated event.
function user_can_view_event_note(array $user, array $event, array $note): bool
{
    if (!user_can_access_scan_event($user, $event)) {
        return false;
    }

    return $note['visibility'] === 'shared'
        || (int) $note['author_operator_id'] === (int) $user['id'];
}

// FR05/SR05: only the author with current event access may edit or delete a note.
function user_can_modify_event_note(array $user, array $event, array $note): bool
{
    return user_can_access_scan_event($user, $event)
        && (int) $note['author_operator_id'] === (int) $user['id'];
}
