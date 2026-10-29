<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/scan_events_repository.php';

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

$filename = $kind === 'thumb' ? $event['thumbnail_filename'] : $event['sixray_image_filename'];

if (!is_string($filename) || $filename === '' || basename($filename) !== $filename) {
    http_response_code(404);
    exit('Not found');
}

$baseDirectory = $kind === 'thumb' ? '/srv/threat_media/thumbnails' : '/srv/threat_media/originals';
$path = $baseDirectory . '/' . $filename;

if (!is_file($path) || !is_readable($path)) {
    http_response_code(404);
    exit('Not found');
}

$mimeType = mime_content_type($path) ?: 'application/octet-stream';
header('Content-Type: ' . $mimeType);
header('Content-Length: ' . (string) filesize($path));
header('Cache-Control: private, max-age=300');
readfile($path);
