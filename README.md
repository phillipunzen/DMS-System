# DMS System — Archivraum

A self-hosted, multi-tenant document management system with local OCR, immutable document versions, optional approval workflows, fine-grained access control and a responsive web/PWA interface. The application name is configurable in Server administration. The current interface language is German; this documentation is in English.

## Features

- Multiple document spaces per account, invitations, tenant quotas and owner/manager/editor/viewer roles.
- Document and folder access lists: read or edit grants intersect with folder restrictions and never exceed the account's tenant role.
- PDF, PNG, JPEG, TIFF and text imports; local German/English Tesseract OCR and direct extraction of existing PDF text.
- Document preview, original downloads, metadata, tags, invoice amounts, due dates, paid status, statistics and search across document metadata and OCR text.
- Immutable file versions; restoring an older version creates a new current version. All historical versions count toward storage usage.
- Optional review/approval workflows per tenant. A different eligible member approves or rejects the current version; document changes invalidate approval and preserve history.
- Mobile camera imports with local rotation/cropping and up to 20 pages per PDF. Camera-generated PDFs discard EXIF/location metadata.
- Tenant-specific scanner folders, automatic filing rules, read-only IMAP ingestion and outgoing CalDAV due-date synchronization.
- Local accounts, LDAP/Microsoft AD, OIDC, optional TOTP two-factor authentication and one-use recovery codes.
- Optional automatic AI metadata extraction through Codex with a ChatGPT subscription or the OpenAI Responses API.
- Password-encrypted tenant backups and restoration into a separate document space.
- Light, dark and blue themes, a configurable PWA manifest and support for multiple domains. Private documents and API responses are never cached for offline use.

## Architecture and images

| Component | Published image | Purpose |
| --- | --- | --- |
| Application | `ghcr.io/phillipunzen/dms-system:latest` | FastAPI web application, OCR and background worker; UID/GID 10001 |
| Private Codex gateway | `ghcr.io/phillipunzen/dms-system-codex:latest` | Official Codex CLI, subscription login and metadata extraction; UID/GID 10002 |
| Database | Your external MariaDB | Database and dedicated credentials supplied through `DATABASE_URL` |

Images target **Linux/amd64**. The default deployment runs one application container and one private Codex container. The Codex service exposes no host port and has no document mount or database credentials. The optional database override runs a local MariaDB 11.4 for evaluation.

[GitHub Actions](https://github.com/phillipunzen/DMS-System/actions) runs SQLite and MariaDB functional tests before publishing both images. Pushes to `main` update `latest` and a `sha-<short-commit>` tag. Version tags such as `v1.0.0` publish `1.0.0`; they do not replace `latest`. A manual workflow run on `main` also publishes images. No Docker Hub credentials are required; the workflow uses GitHub's built-in `GITHUB_TOKEN` with `packages: write`.

**First publication:** GitHub Container Registry initially makes new packages private, even for a public repository. To allow anonymous pulls, the package owner must change each package's visibility to public in **Packages → Package settings**. Until then, authenticate with `docker login ghcr.io -u YOUR_GITHUB_USERNAME` and a personal access token with `read:packages`. See [GitHub's package visibility documentation](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility). Never place that token in the DMS `.env` or commit it.

## Quick start with published images

Requires Docker Engine with the Compose plugin, Python 3 on the host for secret generation, and an existing external MariaDB database. Use a dedicated database user with DDL permissions on that database so Alembic can run schema migrations.

```bash
git clone https://github.com/phillipunzen/DMS-System.git
cd DMS-System
python3 scripts/init_env.py
mkdir -p consume
sudo chown 10001:10001 consume
```

The generator refuses to overwrite an existing `.env`. It creates `.env` and `INITIAL_ACCESS.txt` with mode 0600 and random secrets. Its defaults are for **local HTTP evaluation** with a local database. Before an external-database deployment, edit `.env`:

```dotenv
# Set your external database host and URL-encode the username/password.
DATABASE_URL=mysql+pymysql://dms:URL_ENCODED_PASSWORD@mariadb.internal:3306/dms?charset=utf8mb4
BOOTSTRAP_ADMIN_EMAIL=admin@example.org
# Keep the generated SECRET_KEY, CODEX_SERVICE_TOKEN and bootstrap password.

# For a host reverse proxy with HTTPS:
APP_BIND=127.0.0.1
APP_PORT=8120
COOKIE_SECURE=true
ALLOWED_HOSTS=dms.example.org,archive.example.org

# Default: Docker-managed document volume. For NAS use a mounted absolute path.
DOCUMENTS_PATH=documents
# Use the absolute path to the prepared scanner input directory.
CONSUME_PATH=/srv/dms/consume
MAX_UPLOAD_MB=50
MAX_TENANT_BACKUP_MB=250
IMAGE_TAG=latest
```

Prepare the actual `CONSUME_PATH` with UID/GID 10001 write access. Start the image deployment:

```bash
docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml ps
```

Always use **`-f docker-compose.yml`** for the published-image deployment. The separate `compose.yaml` in this repository is for local source builds and would otherwise take precedence during automatic Compose file discovery. The published-image project name defaults to `dms-system`; the local build configuration uses `dms-archiv`. Their volumes are separate. Do not switch configurations on an existing installation without planning the database and storage paths.

Open your configured HTTPS domain, sign in with the bootstrap email and the password from `INITIAL_ACCESS.txt`, change the password under **Konto → Passwort ändern**, and delete the access file. Bootstrap credentials only create the first administrator when no administrator exists; changing the environment later does not reset an existing account.

### Evaluate with a local database

For direct HTTP evaluation, the generated `.env` already supplies random database passwords and `COOKIE_SECURE=false`. Set `APP_BIND=0.0.0.0` if you want LAN access, and set `ALLOWED_HOSTS` to the server's IP/hostnames. Use both files for every command:

```bash
docker compose -f docker-compose.yml -f docker-compose.db.yml pull
docker compose -f docker-compose.yml -f docker-compose.db.yml up -d
```

Open `http://YOUR_SERVER_IP:8120`. This override creates a persistent `database` volume and does not publish MariaDB's port. The app's database URL is supplied by the override. Do not combine it with your production external database deployment.

### Updates and reproducible deployments

```bash
# First take a coordinated database/document/configuration backup.
docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml logs --tail=100 app
```

`latest` is mutable. For a reproducible deployment, set `IMAGE_TAG` to an available release or `sha-<short-commit>` tag shared by both images, or pin their digests in your deployment copy. Migrations run before the app starts. A schema change may require restoring a coordinated backup to roll back; replacing an image alone is not a database rollback. `docker compose down` preserves named volumes; **`down -v` deletes them**.

## Configuration reference

`docker-compose.yml` includes inline explanations for every application environment variable and mount. No real credentials are included in this repository.

| Variable | Meaning |
| --- | --- |
| `SECRET_KEY` | Random secret of at least 32 characters; encrypts integration and MFA secrets. Keep unchanged and back it up. |
| `DATABASE_URL` | External MariaDB SQLAlchemy/PyMySQL URL, including database name. URL-encode credentials. |
| `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` | Initial administrator; password must contain 12–256 characters. |
| `CODEX_SERVICE_TOKEN` | At least 32 random characters, shared only between the DMS and private gateway; not an OpenAI API key. |
| `APP_BIND` / `APP_PORT` | Published application bind address and port; defaults in the image Compose file are `127.0.0.1:8120`. |
| `COOKIE_SECURE` | `true` behind HTTPS; `false` only for direct HTTP evaluation. |
| `ALLOWED_HOSTS` | Comma-separated IPs/hostnames without scheme/port; further domains can be configured in the admin panel. |
| `DOCUMENTS_PATH` | Docker document volume name or pre-mounted absolute NAS/host directory. |
| `CONSUME_PATH` | Separate scanner input directory; an absolute host path is recommended. |
| `MAX_UPLOAD_MB` | Per-upload limit; default 50 MB. |
| `MAX_TENANT_BACKUP_MB` | Web tenant backup/restore limit; default 250 MB. |
| `IMAGE_TAG` | Tag for both published images; defaults to `latest`. |
| `DB_PASSWORD` / `DB_ROOT_PASSWORD` | Used only by the optional local-database override. Generated hexadecimal values are URL-safe. |

For database TLS, mount the CA file into the application and add PyMySQL URL options such as `&ssl_ca=/run/certs/mariadb-ca.pem&ssl_verify_cert=true&ssl_verify_identity=true`. The database must be reachable from the container; `localhost` refers to the container itself.

## NAS storage, scanner folders and domains

Mount SMB/CIFS or NFS **on the host**, then set `DOCUMENTS_PATH` to the mount path. UID/GID 10001 must be able to create directories, read, write, rename and lock files. Newly created original files use mode 0600; tenant/document directories use 0700 where supported. Apply equivalent NAS permissions and tenant separation. Ensure the NAS is mounted before starting the app so missing mounts cannot silently become local directories.

Storage layout:

```text
<data-root>/<tenant-uuid>/<document-uuid>/original
<data-root>/<tenant-uuid>/<document-uuid>/versions/<number>/original
<consume-root>/<tenant-uuid>/eingang/
<consume-root>/<tenant-uuid>/verarbeitet/   # optional processed-source archive
```

The tenant owner activates the scanner integration under **Integrationen → Scanner-Importordner**. Each tenant gets its own input directory; users cannot select arbitrary server paths. The worker checks approximately every 30 seconds and waits for files to settle (default 30 seconds). Scanners should write a `.part` file and rename it after completion. Hidden/temporary files, symlinks and subdirectories are skipped.

Sources are deleted by default **only after** the original, database metadata and import receipt have been saved and the stored original's checksum verified. Moving sources to `verarbeitet` is optional. Failed or duplicate imports retain the source. OCR follows asynchronously; a later OCR failure does not remove the archived original. Preserve separate permissions for scanner writers and document storage.

Point DNS at your server/reverse proxy. Preserve the original **Host** header and configure additional domains under Server administration; domain selection does not grant tenant membership. Set `COOKIE_SECURE=true` for HTTPS. PWA installation on other devices requires HTTPS; plain-IP HTTP evaluation provides the web interface. Private document access always requires a connection to the server.

## Roles, versions, reviews and account security

| Role | Permissions |
| --- | --- |
| Viewer | Search, view and download accessible documents |
| Editor | Also upload, edit metadata, add versions and manage trash/recovery |
| Manager | Also manage permitted folders, rules and lower-role members |
| Owner | Also configure integrations, access lists, workflows, backups, activity history and membership roles |
| Server administrator | Global settings, quotas, domains, account suspension and external authentication; document access still requires tenant membership |

Folder and document restrictions both apply; an explicit document grant does not bypass a restricted folder. Owners retain access. Search, statistics, previews, downloads, version history and review queues observe these restrictions. Removing a tenant member also removes their individual grants.

At **Dokument → Versionen**, upload a new original or restore a previous one as a new version. Previous files remain unchanged. OCR and enabled automatic AI run again. The new version resets extracted metadata, payment status and approval; title/tags remain. Trash and historical versions continue to count against quota.

Enable optional workflows at **Raumeinstellungen → Prüfabläufe**. A different eligible editor with document access decides on the current version; the requester/uploader cannot approve it themselves. Changes supersede pending reviews and reset approval while retaining history. The approval status is an organizational marker, not a download or payment lock.

Set up a TOTP authenticator under **Konto → Zwei-Faktor-Anmeldung**, confirm a valid code and save the ten one-use recovery codes separately. They are shown only when generated. Activation/deactivation revokes existing sessions. The DMS factor also applies to LDAP/OIDC logins for that account.

## OCR and AI

Local OCR, search, basic invoice extraction and filing rules work without an external AI provider. PDF extraction is limited to 100 pages; image-PDF OCR and TIFF processing to 50 pages. Protected/damaged files enter an error state. Originals are not rewritten into OCR PDFs.

New tenants have AI disabled until the owner configures a provider and consent. The integration dialog offers automatic processing, requiring separate automatic-transfer consent. Existing configurations without that consent remain manual. Manual mode lets the owner edit a minimized preview and explicitly approve the exact text before transmission.

Before either provider is contacted, the server masks recognized email addresses, URLs, common IBAN/phone formats and labeled account/tax/customer identifiers, then limits the OCR excerpt to 1,000–10,000 characters (default 10,000). Original files, filenames and DMS user/tenant identifiers are not included in the AI payload. Pattern masking is **not guaranteed anonymization**: names, addresses, sensitive context or OCR errors may remain. In automatic mode there is no individual preview approval. The server administrator can block all external AI transfers globally.

An AI outage leaves the document and local OCR searchable, with an **AI pending / KI ausstehend** status. Retries back off up to one hour; disabling the integration or globally blocking AI prevents further transfers. AI-derived metadata still requires human verification.

### Codex with a ChatGPT subscription

1. Under **Serveradministration → Codex**, connect your ChatGPT account using the official device-login page linked by the application. ChatGPT passwords are never entered into the DMS. Enable device login in your account/workspace if required.
2. Allow the intended tenants to use the connected subscription in the same admin panel.
3. Under **Integrationen → KI-Metadaten**, select **Codex (ChatGPT-Abonnement)**, activate the integration and explicitly consent to the desired manual/automatic mode.

The gateway uses the official Codex App Server over local stdio, pinned to CLI **0.162.1**. Each document gets a new ephemeral thread, isolated temporary working directory and validated output schema. Shell/tools, browsing, apps, plugins and further agents are disabled. The gateway receives only the minimized text; it cannot access the DMS database or originals. Account access conditions and usage limits apply; there is no automatic paid-API fallback.

The `codex_auth` volume persists sensitive account tokens, owned by UID/GID 10002. Protect and back it up separately; disconnect via the admin panel. For login/data-handling details see [OpenAI's Codex authentication documentation](https://developers.openai.com/codex/auth/) and [App Server documentation](https://developers.openai.com/codex/app-server/). Ephemeral local threads do not guarantee zero provider-side retention.

### OpenAI API

The alternative integration uses your API key and an API-compatible endpoint supporting Responses with Structured Outputs. Requests set `store: false` and use the same minimization and consent controls. API access/billing is separate from the subscription gateway. See [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs). Provider/workspace data controls still apply; `store: false` is not a blanket guarantee of zero retention.

## Other integrations

- **IMAP:** TLS with certificate verification, password/app-password authentication, approximately five-minute polling. Imports supported attachments and optionally plain-text mail; UID/UIDVALIDITY track completed imports. The mailbox is read-only with `BODY.PEEK`; no deletion or outgoing email. OAuth mail login is not implemented. Invitations are copyable expiring links, not automatically sent email.
- **CalDAV:** Configure an existing HTTPS calendar collection. Approximately 15-minute polling creates/updates all-day due-date events and removes paid/trashed documents. Synchronization is DMS → calendar only; a dedicated calendar is recommended. Clean up the previous calendar when changing the URL.
- **LDAP/Microsoft AD:** LDAPS or StartTLS with verified certificates, base DN, bind credentials and escaped email search filter; default `(mail={email})`. The directory must supply `mail`. Mount private CA files if needed. DMS invitations/roles remain locally managed; no automatic group synchronization or email-only conversion of existing local accounts.
- **OIDC:** Configure discovery URL, client ID/secret and exact `<HTTPS-BASE-URL>/api/auth/oidc/callback`. Uses state, nonce, signature/claim checks and PKCE; requires `openid profile email` and `email_verified=true`. New users need invitations or enabled registration. Link an existing account while signed in locally. Verify your actual provider's claims, especially Microsoft Entra.

## Backups and restore

Tenant owners can download a password-encrypted `.dmsbackup` under **Raumeinstellungen**. It includes all file versions, OCR text, metadata, folders, rules and archived permissions/reviews. AES-256-GCM provides encryption and integrity protection; Scrypt derives the key. There is no recovery without the password. The default 250 MB limit suits smaller tenant archives.

Restoration creates a new tenant owned only by the restoring user. Previous users must be reinvited, permissions reapplied and approvals renewed. Archived rights/reviews are available for inspection. Account passwords, MFA secrets and integration credentials are not imported; restoration does not automatically send documents to AI.

For full recovery, coordinate MariaDB, document/NAS storage, scanner input, `.env`/`SECRET_KEY` and Codex auth backups. A database dump without files, or files without metadata, is incomplete. Store backups separately and protect their secrets. [Restore guide](docs/RESTORE.md).

```bash
# Check every stored document version against its SHA-256 checksum.
docker compose -f docker-compose.yml exec app python scripts/check_integrity.py
# Inspect health and logs.
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml logs --tail=100 app
```

`scripts/backup_dev.py` is specifically for the **local source-build development stack** (`compose.yaml` + `compose.dev.yaml`) and stops the app/gateway briefly. It is not an external-MariaDB backup tool. Pause scanner writers during coordinated backups.

## Development and validation

```bash
# Local source builds and a private development database:
python3 scripts/init_env.py  # fresh checkout only; existing .env is preserved
mkdir -p consume
sudo chown 10001:10001 consume
docker compose -f compose.yaml -f compose.dev.yaml up -d --build

# Isolated SQLite tests; real tenant data is untouched.
docker run --rm --entrypoint python -v "$PWD:/app:ro" \
  dms-archiv-app -m pytest tests -q -p no:cacheprovider

# Development-stack backup, outside the repository:
python3 scripts/backup_dev.py /srv/backups/dms-YYYY-MM-DD
```

The test suite covers tenant separation, OCR, versions, access lists, review decisions, MFA, scanner cleanup, encrypted restore, AI consent/minimization and mocked external integrations. CI additionally uses MariaDB 11.4. External MariaDB/NAS, actual identity providers, mail/calendars and live AI accounts need validation against the intended deployment.

This implementation targets one application container rather than a horizontally scaled cluster. Search uses SQL substring matching, without a dedicated index or semantic search. It does not implement WORM storage, tamper-proof audit archives, retention automation, email password reset, office previews, antivirus quarantine, automatic camera perspective correction or realtime notifications. Original retention and an activity log alone do not constitute a legal compliance/revision-safety guarantee.
