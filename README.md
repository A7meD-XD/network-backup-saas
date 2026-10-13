# Network Configuration Backup & Audit API

A FastAPI network-configuration backup and audit service. Local development defaults to SQLite; the Docker deployment uses PostgreSQL. Device passwords are encrypted with Fernet before storage, and the API never returns them.
[![Architecture diagram of a7med-xd/network-backup-saas](https://gitdiagram.com/a7med-xd/network-backup-saas/diagram.png)](https://gitdiagram.com/a7med-xd/network-backup-saas?utm_source=readme&utm_medium=picture)

## Docker Deployment

The Compose deployment uses PostgreSQL 16 with a named persistent volume. It does not automatically migrate an existing SQLite database; use a separate migration/export process if you need to preserve existing SQLite data.

1. Copy the environment template and generate secrets:

	```bash
	cp .env.example .env
	openssl rand -hex 24  # PostgreSQL password
	openssl rand -base64 32 | tr '+/' '-_'  # URL-safe Fernet key
	openssl rand -hex 32  # JWT signing key
	openssl rand -hex 32  # Admin registration token
	```

	Put each generated value in its matching `.env` entry. Keep the Fernet key stable; changing it prevents decrypting device passwords already stored. The hex PostgreSQL password avoids special characters that need URL escaping.

2. Build and start the services:

	```bash
	docker compose up -d --build
	docker compose ps
	```

3. Wait for the `app` and `db` health statuses to become `healthy`, then open `http://localhost:8000/docs` to register the first Admin with the `X-Admin-Registration-Token` from `.env`. The dashboard is at `http://localhost:8000/`.

Useful operations:

```bash
docker compose logs -f app
docker compose down
```

`docker compose down` retains the `postgres_data` volume. `docker compose down -v` deletes the database volume and all persisted data. The app runs one Uvicorn worker because APScheduler is in-process. Put the service behind TLS/authenticated ingress before exposing it beyond a trusted network; the compose port is intended for local access or a protected reverse proxy.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Generate a key, then put the output in DEVICE_ENCRYPTION_KEY inside .env:
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
uvicorn main:app --reload
```

Replace the placeholder `DEVICE_ENCRYPTION_KEY` in `.env` with the generated key and keep it secret and persistent. Losing or changing it makes existing device passwords impossible to decrypt. Add notification credentials only for channels you use. The default database is `network_backup.db` in the current working directory; set `DATABASE_URL` to use another SQLAlchemy database URL.
Also replace `JWT_SECRET_KEY` with a fresh value from `openssl rand -hex 32`; changing this value invalidates existing access tokens. Set `ADMIN_REGISTRATION_TOKEN` to a separate random value and keep it private for initial Admin account creation.
AI diff summaries are optional. Set `GEMINI_API_KEY` to enable them and optionally change `GEMINI_MODEL`. When enabled, the raw unified configuration diff is sent to Google's Gemini API for analysis; ensure your configuration-data handling policy permits this. Without a key, diff requests still succeed and return `ai_summary: null`.
The Gemini request and prompt template are in `app/ai_summary.py` (`DIFF_SUMMARY_PROMPT`). The prompt treats diff content as untrusted data, asks for a concise operational and security impact summary, prohibits following instructions embedded in the diff, and asks the model not to repeat credentials. AI request errors/timeouts are logged without exposing the API key and do not fail the diff endpoint.
Realtime configuration and audit alerts are independently sent to every configured Telegram, Slack, and Teams channel. Missing settings or delivery failure for one channel is logged and does not fail a backup or suppress the other channels.

Configure scheduled email reports with `SMTP_HOST`, `SMTP_FROM_EMAIL`, and comma-separated `SMTP_TO_EMAILS`. Use SMTP port `587` with `SMTP_STARTTLS=true`, or port `465` with `SMTP_USE_SSL=true`; credentials are optional for relays that do not require authentication. Set `REPORT_FREQUENCY=daily` or `weekly`, `REPORT_HOUR`/`REPORT_MINUTE` in UTC, and `REPORT_DAY_OF_WEEK` for weekly reports. The report includes SSH TCP reachability, the latest backup status/time, and current security findings. If SMTP settings are incomplete the scheduled report is skipped safely.

The app reads `.env` automatically. Set `BACKUP_INTERVAL_HOURS` there to change the scheduled interval; it defaults to `24`. The first automatic sweep runs after one full interval, then repeats on that interval. Start one Uvicorn worker for this in-process scheduler; multiple workers would each run their own scheduled sweep.

## API

- `POST /auth/register` creates a Viewer account by default. To create an Admin, request `role: "Admin"` and include `X-Admin-Registration-Token` with the configured bootstrap token. Never expose this token to ordinary users.
- `POST /auth/login` accepts OAuth2 form fields `username` (the email address) and `password`, and returns a 30-minute JWT access token.
- Send `Authorization: Bearer <access_token>` on protected API requests. In `/docs`, use the **Authorize** control to apply the token.
- `GET /api/dashboard` requires Admin or Viewer and returns SSH-port reachability, latest successful backup time/count, and current audit findings for the dashboard. Reachability uses a short TCP connection check to each device's SSH port.
- `GET /healthz` is an unauthenticated readiness probe for Docker; it returns healthy only when the configured database accepts a query.
- `POST /devices` registers a device. Requires Admin. Required fields: `hostname`, `ip_address`, `device_type`, `username`, and `password`; `ssh_port` defaults to `22`.
- `GET /devices` lists registered devices without password fields. Requires Admin or Viewer.
- `GET /` opens the device dashboard. It displays the latest backup and audit findings, starts backups, and shows added/removed lines in a diff view.
- `POST /api/devices/{device_id}/backup` requires Admin; it connects over SSH with Netmiko, runs the platform's configured command, and stores a successful backup. SSH timeouts return `504`; authentication failures return `401`.
- `POST /api/devices/bulk-exec` requires Admin and accepts `{"device_ids": [1, 2], "commands": ["show clock", "show version"]}`. It runs at most 10 device connections concurrently for up to 50 devices and 20 single-line commands. Per-device status and output are returned to the Admin; output is not persisted and may contain secrets.
- `GET /api/compliance` requires Admin or Viewer and returns latest-backup evaluations plus a `non_compliant_devices` list with severity, explanation, and remediation. Devices without successful backups are marked not evaluated.
- `GET /api/compliance/rules` lists enabled and disabled rules. `POST /api/compliance/rules` (Admin only) adds a Python-regex rule with `name`, `description`, `pattern`, `remediation`, and `severity`.
- `POST /api/devices/{device_id}/restore` requires Admin and pushes a successful saved configuration using Netmiko `send_config_set`. Omit the JSON body to use the latest successful backup, or pass `{"backup_id": 12}` to select one. Sensitive values in the response are redacted.
- `GET /api/devices/{device_id}/diff` requires Admin or Viewer. It compares the latest successful backup with the preceding one and returns unified and structured differences.
- Each diff response includes `ai_summary`, a concise operational/security explanation generated from the unified diff when Gemini is configured. The dashboard displays this above the added/removed lines.
- `GET /api/compliance/rules` lists enabled and disabled rules. `POST /api/compliance/rules` (Admin only) adds a Python-regex rule with `name`, `description`, `pattern`, `remediation`, and `severity`. Built-in rules check remote logging and NTP; the dashboard shows non-compliant devices with clear remediation.
- Every successful backup is scanned for platform-specific security findings. Configuration changes and audit findings are sent to configured notification channels.
- `GET /docs` opens the interactive OpenAPI documentation.

Example Admin setup and authenticated device registration:

```bash
curl -X POST http://127.0.0.1:8000/auth/register \
	-H 'Content-Type: application/json' \
	-H "X-Admin-Registration-Token: $ADMIN_REGISTRATION_TOKEN" \
	-d '{"email":"admin@example.com","password":"change-this-password","role":"Admin"}'

TOKEN=$(curl -sS -X POST http://127.0.0.1:8000/auth/login \
	-H 'Content-Type: application/x-www-form-urlencoded' \
	-d 'username=admin@example.com&password=change-this-password' | jq -r .access_token)

curl -X POST http://127.0.0.1:8000/devices \
	-H "Authorization: Bearer $TOKEN" \
	-H 'Content-Type: application/json' \
	-d '{"hostname":"edge-01","ip_address":"192.0.2.1","device_type":"cisco_ios","username":"operator","password":"device-password"}'
```

Public Viewer signup omits the `role` field. Login uses OAuth2 form encoding; use the returned `access_token` as the Bearer token.

The `devices`, `backups`, `users`, `compliance_rules`, `bulk_command_batches`, and `bulk_command_results` tables are created automatically on application startup. Built-in rules check remote logging and NTP server configuration; additional rules can be added with the API. Bulk execution history stores the requesting user, batch status, device-level result status, and error category; raw CLI output and command text are not persisted. Supported backup platforms and commands are `cisco_ios` (`show running-config`), `mikrotik_routeros` (`export`), `juniper_junos` (`show configuration`), and `fortinet` (`show full-configuration`). Add further Netmiko platform identifiers and commands in `app/network.py`'s `BACKUP_COMMANDS` map.

Notification integrations are modular under `app/notifications/`: `slack.py`, `teams.py`, `email_reports.py`, and `report.py`. `notifier.py` fans out real-time change/audit notifications; `scheduler.py` triggers the configured email summary schedule.

The security audit applies Cisco IOS password-encryption and VTY checks only to Cisco platforms, and parses common Telnet/SNMP indicators in RouterOS, Junos, and FortiOS output. Diff processing normalizes line endings, ANSI terminal escapes, blank/trailing whitespace, and known volatile config headers while preserving platform syntax.

## Troubleshooting

- `POST /devices` returns `503`: set a valid, persistent `DEVICE_ENCRYPTION_KEY` before starting Uvicorn. Generate one with `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`. Use the same key on every restart; changing it prevents decryption of passwords already stored in the database.
- `POST /api/devices/{device_id}/backup` returns `404 Device not found`: device creation did not complete or the ID is wrong. After setting the key, create the device again and use the `id` from its `201 Created` response, or check IDs with `GET /devices`.

On every app startup, the FastAPI lifespan runs `Base.metadata.create_all(bind=engine)` after importing the `Device` and `Backup` models. This creates missing tables without deleting existing rows.

The HTML dashboard at `/` contains no device data until a user signs in; its browser stores the short-lived token in session storage and sends it with protected API requests. Restore reapplies commands from a saved configuration; it does not remove newer settings that are absent from that backup, so it is not an exact device rollback. Keep the service behind trusted network access and TLS before exposing it outside a local test environment.

## Local SSH Mock

For local testing, start the mock router in a separate terminal:

```bash
python mock_router.py
```

It listens only on `127.0.0.1:2222`, accepts username `admin` and password `admin123`, and serves a sample Cisco-style running configuration. Register it with the API:

```bash
curl -X POST http://127.0.0.1:8000/devices \
  -H "Authorization: Bearer $TOKEN" \
	-H 'Content-Type: application/json' \
	-d '{"hostname":"mock-router","ip_address":"127.0.0.1","device_type":"cisco_ios","username":"admin","password":"admin123","ssh_port":2222}'
```

Use the returned device ID for authenticated backup requests. The existing dashboard page is not bearer-protected and its browser actions do not yet attach the JWT; call the APIs with the token until dashboard login is added. This mock is for local development only; do not expose it to a network.
