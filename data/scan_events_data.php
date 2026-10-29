<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/scan_events_repository.php';

$user = require_auth();
$filters = normalize_scan_event_filters($_GET);
$payload = fetch_scan_event_dashboard_payload($user, $filters);

header('Content-Type: application/json; charset=UTF-8');
echo json_encode($payload, JSON_THROW_ON_ERROR);
