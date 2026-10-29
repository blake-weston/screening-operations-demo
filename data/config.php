<?php

declare(strict_types=1);

return [
    'app_name' => 'Airport Security CT Scan Monitor',
    'db' => [
        'host' => getenv('DB_HOST') ?: 'db',
        'port' => (int) (getenv('DB_PORT') ?: '3306'),
        'database' => getenv('DB_DATABASE') ?: 'airport_security',
        'username' => getenv('DB_USERNAME') ?: 'app',
        'password' => getenv('DB_PASSWORD') ?: 'app_password',
        'charset' => 'utf8mb4',
    ],
];
