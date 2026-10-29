# Airport Security CT Scan Monitor

A secure proof-of-concept dashboard for reviewing airport CT screening events. The application provides authenticated access, role-based permissions, lane-scoped visibility, scan-event filtering, protected threat imagery, and administrator account management.

## Presentation

Watch the [airport security application presentation on YouTube](https://youtu.be/0zBchxDMKqA?si=TPPEcZ2pLZD_3iCe).

## Technology

- nginx reverse proxy with HTTPS
- PHP 8.3 and Apache
- MySQL 8.4
- Docker Compose

## Requirements

- Docker Desktop, or Docker Engine with Docker Compose
- Ports `8443` and `3306` available on the host

## Run the application

Build and start the containers:

```sh
docker compose up -d --build
```

On a fresh database, import the seeded threat imagery:

```sh
docker compose exec web php /var/www/html/scripts/import_threat_media.php
```

Open [https://localhost:8443](https://localhost:8443) in a browser. The included certificate is self-signed and intended for local development, so the browser may display a certificate warning.

## Demo accounts

| Role | Username | Password |
| --- | --- | --- |
| Administrator | `admin` | `admin123` |
| Manager | `manager.t2` | `manager123` |
| Lane operator | `lane.t2.a` | `lane123` |

These intentionally simple credentials are for demonstration only and must not be used in a production deployment.

## Useful commands

Check container status:

```sh
docker compose ps
```

View logs:

```sh
docker compose logs -f
```

Stop the application while retaining database data:

```sh
docker compose down
```

Remove the containers and database volume for a completely fresh start:

```sh
docker compose down --volumes
```

## Project structure

```text
data/           PHP application
db/init/        Database schema and seed data
nginx/          Reverse-proxy configuration and local TLS certificate
threat_media/   Import assets, originals, and thumbnails
Dockerfile      PHP/Apache image definition
docker-compose.yml
```

## Scope and security notice

This is an academic prototype, not a production airport system. It has no live scanner integration and uses seeded demonstration data. The Compose configuration contains local development database credentials, and the repository includes a self-signed private key used only for local HTTPS. Production deployment would require proper secret management, trusted certificates, unique credentials, monitoring, backups, and additional operational controls.
