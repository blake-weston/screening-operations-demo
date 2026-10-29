<?php

declare(strict_types=1);

return [
    'app_name' => 'Airport Security CT Scan Monitor',
    'db' => [
        'host' => getenv('DB_HOST') ?: 'db',
        'port' => (int) (getenv('DB_PORT') ?: '3306'),
        'database' => getenv('DB_DATABASE') ?: 'airport_security',
        // SR10: credentials must be supplied by the deployment, never by tracked fallback values.
        'username' => getenv('DB_USERNAME') ?: throw new RuntimeException('DB_USERNAME is required.'),
        'password' => getenv('DB_PASSWORD') ?: throw new RuntimeException('DB_PASSWORD is required.'),
        'charset' => 'utf8mb4',
    ],
];
