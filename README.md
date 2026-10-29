# Airport Security CT Scan Monitor

A proof-of-concept dashboard for reviewing airport CT screening events. It provides authenticated access, role-based permissions, lane-scoped event visibility, protected threat imagery, administrator account management, and private or shared operational notes.

## Presentation

Watch the [airport security application presentation on YouTube](https://youtu.be/0zBchxDMKqA?si=TPPEcZ2pLZD_3iCe).

## Technology

- nginx reverse proxy with local HTTPS
- PHP 8.4 and Apache
- MySQL 8.4
- Docker Compose

## Requirements

- Docker Desktop, or Docker Engine with Docker Compose
- OpenSSL for generating the local development certificate
- Port `8443` available on the host

## Run the application

Create a local environment file and replace every placeholder with a distinct value:

```sh
cp .env.example .env
chmod 600 .env
```

Generate a self-signed certificate for `localhost`. The generated certificate and private key are ignored by Git:

```sh
./scripts/generate-local-certificates.sh
```

Build and start the containers:

```sh
docker compose up -d --build
```

On a fresh database, import the seeded threat imagery:

```sh
docker compose exec web php /var/www/html/scripts/import_threat_media.php
```

Open [https://localhost:8443](https://localhost:8443). Because the certificate is self-signed, the browser will display a certificate warning.

## Demo accounts

| Role | Username | Password |
| --- | --- | --- |
| Administrator | `admin` | `admin123` |
| Manager | `manager.t2` | `manager123` |
| Lane operator | `lane.t2.a` | `lane123` |

These intentionally simple credentials are for demonstration only.

## Existing database volumes

MySQL runs files from `db/init/` only when it creates an empty data directory. To add event notes to an existing baseline volume, back up the database and then apply the migration:

```sh
docker compose exec -T db sh -c \
  'mysql -u root -p"$MYSQL_ROOT_PASSWORD" airport_security' \
  < db/init/002_event_notes.sql
```

Changing `.env` does not update credentials already stored in an existing MySQL volume. The operational SQL files in `scripts/` can be used to rotate database credentials and restrict the application account to CRUD access. Review their variables and comments before applying them with an administrative account.

## Useful commands

```sh
docker compose ps
docker compose logs -f
docker compose down
```

To remove the containers and database volume for a completely fresh start:

```sh
docker compose down --volumes
```

This permanently deletes the local database volume.

## Project structure

```text
apache/         Apache security configuration
data/           PHP application
db/init/        Database schema, seed data, and event-notes migration
nginx/          Reverse-proxy configuration and generated local certificate directory
scripts/        Local certificate and database administration scripts
threat_media/   Demonstration import assets, originals, and thumbnails
Dockerfile      PHP/Apache image definition
docker-compose.yml
```

## Scope and security notice

This is an academic prototype, not a production airport system. It has no live scanner integration and uses seeded demonstration data. Database credentials are read from the ignored local `.env` file. Production deployment would require managed secrets, trusted certificates, monitoring, backups, credential rotation, and further operational controls.
