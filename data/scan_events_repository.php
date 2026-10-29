<?php

declare(strict_types=1);

function allowed_risk_levels(): array
{
    return ['Low', 'Medium', 'High'];
}

function allowed_terminals(): array
{
    return ['Terminal 2'];
}

function allowed_lane_numbers(): array
{
    return [1, 2, 3, 4];
}

function normalize_scan_event_filters(array $input): array
{
    $riskLevel = trim((string) ($input['risk_level'] ?? ''));
    $terminal = trim((string) ($input['terminal'] ?? ''));
    $laneNumberRaw = $input['lane_number'] ?? null;

    if ($riskLevel !== '' && !in_array($riskLevel, allowed_risk_levels(), true)) {
        $riskLevel = '';
    }

    if ($terminal !== '' && !in_array($terminal, allowed_terminals(), true)) {
        $terminal = '';
    }

    $laneNumber = null;
    if ($laneNumberRaw !== null && $laneNumberRaw !== '') {
        $candidate = filter_var($laneNumberRaw, FILTER_VALIDATE_INT);
        if ($candidate !== false && in_array($candidate, allowed_lane_numbers(), true)) {
            $laneNumber = $candidate;
        }
    }

    return [
        'risk_level' => $riskLevel,
        'terminal' => $terminal,
        'lane_number' => $laneNumber,
    ];
}

function build_scan_event_query_parts(array $user, array $filters): array
{
    $clauses = [];
    $parameters = [];

    if ($filters['risk_level'] !== '') {
        $clauses[] = 'risk_level = :risk_level';
        $parameters['risk_level'] = $filters['risk_level'];
    }

    if ($filters['terminal'] !== '') {
        $clauses[] = 'terminal_name = :terminal_name';
        $parameters['terminal_name'] = $filters['terminal'];
    }

    if ($filters['lane_number'] !== null) {
        $clauses[] = 'lane_number = :lane_number';
        $parameters['lane_number'] = $filters['lane_number'];
    }

    if ($user['role'] === 'lane') {
        $assignments = $user['lane_assignments'];

        if ($assignments === []) {
            $clauses[] = '1 = 0';
        } else {
            $assignmentClauses = [];
            foreach ($assignments as $index => $assignment) {
                $terminalKey = 'assignment_terminal_' . $index;
                $laneKey = 'assignment_lane_' . $index;
                $assignmentClauses[] = "(terminal_name = :{$terminalKey} AND lane_number = :{$laneKey})";
                $parameters[$terminalKey] = $assignment['terminal_name'];
                $parameters[$laneKey] = (int) $assignment['lane_number'];
            }
            $clauses[] = '(' . implode(' OR ', $assignmentClauses) . ')';
        }
    }

    return [$clauses, $parameters];
}

function fetch_scan_event_dashboard_payload(array $user, array $filters): array
{
    [$clauses, $parameters] = build_scan_event_query_parts($user, $filters);

    $query = 'SELECT id, scan_time, terminal_name, lane_number, scanner_location, risk_level, threat_category, notes, thumbnail_filename, sixray_image_filename
              FROM scan_events';

    if ($clauses !== []) {
        $query .= ' WHERE ' . implode(' AND ', $clauses);
    }

    $query .= ' ORDER BY scan_time DESC, id DESC';

    $statement = db()->prepare($query);
    $statement->execute($parameters);
    $events = $statement->fetchAll();

    $summaryQuery = "SELECT
        COUNT(*) AS total_events,
        SUM(risk_level = 'High') AS high_risk_events,
        MAX(scan_time) AS latest_scan_time
     FROM scan_events";

    if ($clauses !== []) {
        $summaryQuery .= ' WHERE ' . implode(' AND ', $clauses);
    }

    $summaryStatement = db()->prepare($summaryQuery);
    $summaryStatement->execute($parameters);
    $summary = $summaryStatement->fetch() ?: [
        'total_events' => 0,
        'high_risk_events' => 0,
        'latest_scan_time' => null,
    ];

    return [
        'summary' => [
            'total_events' => (int) ($summary['total_events'] ?? 0),
            'high_risk_events' => (int) ($summary['high_risk_events'] ?? 0),
            'latest_scan_time' => $summary['latest_scan_time'] ?? null,
        ],
        'events' => array_map(
            static function (array $event): array {
                return [
                    'id' => (int) $event['id'],
                    'scan_time' => (string) $event['scan_time'],
                    'terminal_name' => (string) $event['terminal_name'],
                    'lane_number' => (int) $event['lane_number'],
                    'scanner_location' => (string) $event['scanner_location'],
                    'risk_level' => (string) $event['risk_level'],
                    'threat_category' => (string) $event['threat_category'],
                    'notes' => (string) $event['notes'],
                    'has_thumbnail' => !empty($event['thumbnail_filename']),
                ];
            },
            $events
        ),
    ];
}

function user_can_access_scan_event(array $user, array $event): bool
{
    if ($user['role'] !== 'lane') {
        return true;
    }

    foreach ($user['lane_assignments'] as $assignment) {
        if (
            $assignment['terminal_name'] === $event['terminal_name']
            && (int) $assignment['lane_number'] === (int) $event['lane_number']
        ) {
            return true;
        }
    }

    return false;
}

function fetch_accessible_scan_event_media(array $user, int $eventId): ?array
{
    $statement = db()->prepare(
        'SELECT id, terminal_name, lane_number, sixray_image_filename, thumbnail_filename
         FROM scan_events
         WHERE id = :id
         LIMIT 1'
    );
    $statement->execute(['id' => $eventId]);
    $event = $statement->fetch();

    if (!$event || !user_can_access_scan_event($user, $event)) {
        return null;
    }

    return $event;
}

function risk_badge_class(string $riskLevel): string
{
    return match (strtolower($riskLevel)) {
        'low' => 'badge badge-low',
        'medium' => 'badge badge-medium',
        'high' => 'badge badge-high',
        default => 'badge',
    };
}
