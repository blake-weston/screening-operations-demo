<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/scan_events_repository.php';
require_once __DIR__ . '/media_paths.php';

$user = require_auth();

$eventId = filter_input(INPUT_GET, 'event_id', FILTER_VALIDATE_INT);
$kind = (string) ($_GET['kind'] ?? 'thumb');

if (!$eventId || !in_array($kind, ['thumb', 'full'], true)) {
    http_response_code(400);
    exit('Bad request');
}

$event = fetch_accessible_scan_event_media($user, $eventId);

if (!$event) {
    http_response_code(404);
    exit('Not found');
}

$baseDirectory = $kind === 'thumb' ? '/srv/threat_media/thumbnails' : '/srv/threat_media/originals';
$filename = $kind === 'thumb' ? $event['thumbnail_filename'] : $event['sixray_image_filename'];
$path = resolve_protected_media_path($baseDirectory, $filename);

if ($path === null) {
    http_response_code(404);
    exit('Not found');
}

$mimeType = mime_content_type($path) ?: 'application/octet-stream';
header('Content-Type: ' . $mimeType);
header('Content-Length: ' . (string) filesize($path));
header('Cache-Control: private, max-age=300');
readfile($path);
