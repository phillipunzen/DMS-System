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
- Per-tenant SFTP scanner accounts with generated credentials, optional explicitly enabled FTP, Web UI managed SMB/NFS storage, tenant-specific scanner folders, automatic filing and filename rules, read-only IMAP ingestion and outgoing CalDAV due-date synchronization.
- Local accounts, LDAP/Microsoft AD, OIDC, optional TOTP two-factor authentication and one-use recovery codes.
- Optional automatic AI metadata extraction through Codex with a ChatGPT subscription or the OpenAI Responses API.
- Duplicate prevention including historical versions, and a permission-filtered view of similar OCR texts.
- Atomic bulk edits: move, replace tags, set type/payment status, trash/restore and reprocess up to 100 documents.
- Contract terms, cancellation deadlines and in-app reminders.
- Expiring, revocable, version-pinned external download links with optional passwords.
- Document notes and version-bound PDF highlights/comments; originals remain unchanged.
- Server health overview: worker heartbeat, storage, OCR tools, queues, import errors and backup exports.
- Password-encrypted tenant backups and restoration into a separate document space.
- Light, dark and blue themes, a configurable PWA manifest and support for multiple domains. Private documents and API responses are never cached for offline use.

## Architecture and images

| Component | Published image | Purpose |
| --- | --- | --- |
| Application | `ghcr.io/phillipunzen/dms-system:latest` | FastAPI web application, OCR and background worker; UID/GID 10001 |
| NAS manager | `ghcr.io/phillipunzen/dms-system:latest` | Separate root helper for SMB/NFS mounts and verified storage migration; no database or app secret |
| Scanner gateway | `ghcr.io/phillipunzen/dms-system:latest` | Upload-only SFTP/optional FTP; unprivileged UID/GID 10001 |
| Private Codex gateway | `ghcr.io/phillipunzen/dms-system-codex:latest` | Official Codex CLI, subscription login and metadata extraction; UID/GID 10002 |
| Database | Your external MariaDB | Database and dedicated credentials supplied through `DATABASE_URL` |

Images target **Linux/amd64**. The default deployment runs the application, isolated NAS manager, scanner gateway and private Codex gateway. The NAS manager alone has mount capabilities; it has no Docker socket. The Codex service exposes no host port and has no document mount or database credentials. The optional database override runs a local MariaDB 11.4 for evaluation.

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
# One-time preparation for mount propagation from the NAS manager:
sudo python3 scripts/prepare_storage.py /srv/dms-system/nas
```

The generator refuses to overwrite an existing `.env`. It creates `.env` and `INITIAL_ACCESS.txt` with mode 0600 and random secrets. Its defaults are for **local HTTP evaluation** with a local database. Before an external-database deployment, edit `.env`:

```dotenv
# Set your external database host and URL-encode the username/password.
DATABASE_URL=mysql+pymysql://dms:URL_ENCODED_PASSWORD@mariadb.internal:3306/dms?charset=utf8mb4
BOOTSTRAP_ADMIN_EMAIL=admin@example.org
# Keep the generated SECRET_KEY, CODEX_SERVICE_TOKEN, STORAGE_SERVICE_TOKEN and bootstrap password.

# For a host reverse proxy with HTTPS:
APP_BIND=127.0.0.1
APP_PORT=8120
COOKIE_SECURE=true
ALLOWED_HOSTS=dms.example.org,archive.example.org

# Local starting storage; configure SMB/NFS later in the web UI.
DOCUMENTS_PATH=documents
# Use the absolute path to the prepared scanner input directory.
CONSUME_PATH=/srv/dms/consume
MAX_UPLOAD_MB=50
MAX_TENANT_BACKUP_MB=250
IMAGE_TAG=latest
NAS_MOUNT_PATH=/srv/dms-system/nas
SCANNER_PUBLIC_HOST=dms.example.org
SCANNER_BIND=0.0.0.0
SFTP_PORT=2222
FTP_PORT=2121
```

Prepare the actual `CONSUME_PATH` with UID/GID 10001 write access. Start the image deployment:

```bash
docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml ps
```

Always use **`-f docker-compose.yml`** for the published-image deployment. The separate `compose.yaml` in this repository is for local source builds and would otherwise take precedence during automatic Compose file discovery. The published-image project name defaults to `dms-system`; the local build configuration uses `dms-archiv`. Their volumes are separate. Do not switch configurations on an existing installation without planning the database and storage paths.

Open your configured HTTPS domain, sign in with the bootstrap email and the password from `INITIAL_ACCESS.txt`, change the password under **Konto → Passwort ändern**, and delete the access file. Bootstrap credentials only create the first administrator when no administrator exists; changing the environment later does not reset an existing account.

### Dedicated Linux server with host networking

For a dedicated Linux Docker host or VM, add `docker-compose.host.yml` to use host networking for the application, scanner, NAS manager and Codex gateway. Requires Docker Compose **2.24.0 or later**. The override also works with the source-build `compose.yaml`. Host networking removes Docker port translation; listeners bind directly to the selected host ports. Use these variables in `.env`:

```dotenv
APP_BIND=0.0.0.0
APP_PORT=8120
SCANNER_BIND=0.0.0.0
SCANNER_PUBLIC_HOST=192.168.10.70
SFTP_PORT=2222
FTP_PORT=2121
FTP_PASSIVE_MIN=30000
FTP_PASSIVE_MAX=30009
# Private helpers are always bound to 127.0.0.1 in this configuration.
CODEX_PORT=8001
STORAGE_PORT=8002
DATABASE_URL=mysql+pymysql://dms:URL_ENCODED_PASSWORD@mariadb.internal:3306/dms?charset=utf8mb4
```

Replace the example IP with the new server's address, set `ALLOWED_HOSTS` accordingly, and keep all chosen ports distinct and free. With a host reverse proxy, use `APP_BIND=127.0.0.1` and enable secure cookies for HTTPS. Prepare the NAS shared bind mount and scanner input directory as described above, then run:

```bash
docker compose -f docker-compose.yml -f docker-compose.host.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.host.yml pull
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d
```

Use both files for every subsequent update, status or stop command. Allow the web and SFTP ports in the host firewall for the intended clients; allow FTP and its passive range only if needed. Docker `ports:` mappings are removed by this override. Port changes in `.env` take effect when Compose recreates the services. The scanner address configured in the Web UI must match the actual listener ports; that form does not reconfigure listeners. FTP accounts remain optional and require explicit tenant activation.

The NAS and Codex control APIs use loopback only and retain authentication tokens. Host networking shares the host network namespace, so these internal APIs are reachable by other local host processes; use a dedicated trusted host. Host networking **does not grant NAS mount privileges**. Native SMB/NFS mounts require the existing NAS helper capabilities and a host kernel that permits them; an unprivileged LXC cannot gain those permissions through network mode alone. Prefer a VM or regular Linux server. No fully privileged container or Docker socket is required.

For evaluation with the optional local database, use all four files in this order. The database remains on its bridge network and publishes only `127.0.0.1:${DB_PORT:-3307}`; the override supplies the application/scanner connection URL automatically:

```bash
docker compose -f docker-compose.yml -f docker-compose.db.yml -f docker-compose.host.yml -f docker-compose.host-db.yml up -d
```

Set `DB_PORT` in `.env` if 3307 is occupied. Production with an external MariaDB only needs the first two files. See [Docker's host networking documentation](https://docs.docker.com/engine/network/drivers/host/) for network behavior.

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
| `DOCUMENTS_PATH` | Local starting document volume or host directory. Web UI NAS migration retains the original copy. |
| `CONSUME_PATH` | Separate scanner input directory; an absolute host path is recommended. |
| `MAX_UPLOAD_MB` | Per-upload limit; default 50 MB. |
| `MAX_TENANT_BACKUP_MB` | Web tenant backup/restore limit; default 250 MB. |
| `IMAGE_TAG` | Tag for both published images; defaults to `latest`. |
| `DB_PASSWORD` / `DB_ROOT_PASSWORD` | Used only by the optional local-database override. Generated hexadecimal values are URL-safe. |

For database TLS, mount the CA file into the application and add PyMySQL URL options such as `&ssl_ca=/run/certs/mariadb-ca.pem&ssl_verify_cert=true&ssl_verify_identity=true`. The database must be reachable from the container; `localhost` refers to the container itself.

## NAS storage, scanner folders and domains

### Connect SMB or NFS in the web UI

Under **Speicher & Scanner → NAS-Verbindung**, the server administrator chooses SMB or NFS, enters the NAS host, share/export and an application subdirectory, and tests the connection. SMB additionally needs a username/password and optional domain. NFS supports versions 3, 4, 4.1 and 4.2 and requires read/write access for UID/GID **10001**. SMB mounts use SMB 3.0 with UID/GID 10001, file mode 0600 and directory mode 0700. Use a dedicated NAS account/export restricted to this application.

**NFS v3 / UniFi Drive:** NFS v3 uses TCP, reserved source ports and `nolock` so the read-only mount container does not require `rpc.statd`/NLM services. File locks still coordinate the API and worker on the same Linux host and propagated mount; they do not coordinate other NFS clients. Use a dedicated DMS subtree managed by one DMS installation on one host. NFS v4 retains its normal protocol locking. The helper alone has `NET_BIND_SERVICE` for reserved RPC source ports; the app/scanner do not receive it.

For UniFi Drive, enable NFS under **Settings → Services**, allow the DMS server's IP in the Shared Drive's NFS access configuration, and enter the full exported path in the DMS, for example `/var/nfs/shared/DMS`. Put the NAS address in the **NAS-Server** field separately; do not prepend `IP:` in the export field. Keep version **3** when the NAS export uses NFS v3. See [Ubiquiti's Linux NFS guide](https://help.ui.com/hc/en-us/articles/26277250895895-Accessing-Your-UniFi-Drive-from-Linux-Desktop-Using-NFS). The DMS checks read/write access as UID/GID 10001; an NFS squash mapping must also permit those effective requests. Native NAS connectivity still requires a host that allows kernel mounts.

**Automatic NAS reconnect:** The storage helper checks the saved connection immediately after starting and repeats the check every 20 seconds after each attempt. It verifies access as UID/GID 10001 with a temporary write/read probe, rather than trusting an existing mount entry. A missing or stale mount is replaced with a fresh, verified connection to the same saved NAS/export/subdirectory under the storage migration lock; the active state changes atomically only after success. Preparing the fresh mount does not hold the file-access gate, so logins and administration remain available during connection timeouts. No archived documents or scanner files are copied or deleted during automatic reconnect. Failures retain the saved configuration and are retried; active file transfers postpone the switch. The admin panel shows the last check and automatic recovery status without displaying credentials. Application startup and helper health remain independent of NAS availability.

**NAS outage recovery:** API startup and the application health check do not require access to the active NAS. Administration remains available while the NAS is offline; document access does not fall back to local storage. The worker checks the NAS before selecting queued documents and pauses on an inaccessible mount. Under **Speicher & Scanner**, test the saved connection and use **Speicher aktivieren & Dateien übernehmen** with the same protocol, host, export/share and application subdirectory to reconnect the existing archive without copying it from the failed mount. Keep these values unchanged when recovering; choosing a different target requires the old files to be readable for verified migration.

A propagated NFS mount can remain visible after its original Docker bridge network is removed, while filesystem operations fail with `Network is unreachable`. For a dedicated server, consistently include `docker-compose.host.yml` (and `docker-compose.host-db.yml` when using the optional local database) in your deployment commands. After changing the networking mode, reconnect the same NAS through the web UI. Do not delete storage state, volumes or archive directories to repair a connection.

The separate `storage` container performs mounts. Its HTTP control API has no published host port, requires a random `STORAGE_SERVICE_TOKEN`, and has no database credentials, `SECRET_KEY`, Docker socket or unrestricted privileged mode. Only this helper has `SYS_ADMIN` and the small set of file/user capabilities it needs. Its AppArmor profile is disabled for native mounts; the app and scanner retain dropped capabilities. The Docker host must allow native CIFS/NFS mounts and have the corresponding kernel support. An unprivileged LXC cannot perform native CIFS/NFS mounts merely by enabling mount feature flags. For Web UI managed native mounts, run Docker in a VM or on a normal Linux host. On Proxmox, a privileged LXC with the CIFS/NFS mount features is another deployment option, but do not toggle the existing container’s unprivileged flag: plan a separate properly restored container. Alternatively mount the NAS on the Proxmox host and pass it through to an unprivileged LXC; this uses operator-managed `DOCUMENTS_PATH`/`CONSUME_PATH` and the NAS connection then belongs to the host. See [Proxmox container documentation](https://github.com/proxmox/pve-docs/blob/master/pct.adoc).

**One-time host setup is still required**, but NAS credentials and individual connections are then managed centrally in the UI. Native mounts must propagate between containers. Run `scripts/prepare_storage.py` on a dedicated absolute host directory, and set `NAS_MOUNT_PATH` to that path. This prepares a shared bind parent; it does not mount your NAS. Docker named volumes cannot provide bind mount propagation. Reapply the preparation after a host reboot. For a permanent setup, install the supplied `scripts/dms-nas-mounts.service` in `/etc/systemd/system/`, adjust its paths if necessary, then enable it with `sudo systemctl enable --now dms-nas-mounts.service`. The supplied unit checks for an existing mount and is safe to apply after the preparation script.

**Speicher aktivieren & Dateien übernehmen** pauses concurrent API file access, worker imports and scanner transfers through a shared lock. If a transfer/job is still active, retry once it finishes. All existing document versions and scanner sources are copied, synced and checksum verified before an atomic storage-state switch. Conflicting destination files and symlinks abort migration. The old copy is retained; manually retire it only after verification and a separate backup. The same migration mechanism can switch back to local storage. Applying new credentials or a different NFS version to the same protocol/host/share/subdirectory reconnects that existing NAS tree without copying it; this also permits recovery after a missing mount. A different target requires the previous storage to remain readable so migration can verify the source. A test creates and removes a small temporary file and prepares the application subdirectories without switching storage.

The NAS contains `<subdirectory>/documents` and `<subdirectory>/consume`, each separated by tenant UUID. Encrypted NAS credentials and active storage state persist in `storage_state`; the app database also stores encrypted configuration. Mount flags are `nosuid,nodev,noexec`. After a helper restart, missing mounts are retried approximately every 20 seconds. Every document/inbox path verifies the expected NAS mount in its own container namespace. A missing mount blocks file access rather than writing into the underlying local directory. An unreachable but still mounted NFS server uses hard mounts: file operations may wait until the NAS returns; it never switches to local storage automatically. The UI's “Eingebunden” status confirms the kernel mount; use **Verbindung prüfen** to test actual NAS reachability/read/write.

A pre-mounted `DOCUMENTS_PATH` remains possible for operator-managed storage. Automatic mount checks apply to **Web UI managed** NAS connections; for an operator-managed local-mode path, the operator must guarantee the host mount before starting containers.

### Generate a scanner connection per tenant

The tenant owner opens **Integrationen → Scanner-Importordner** (or **Archiv-Import → Scanner & Import konfigurieren**), selects **SFTP**, **FTP**, or **SFTP und FTP**, enables the integration and saves. Direct server-folder input remains available. Transfer settings and import settings are saved together. The UI generates a dedicated username and strong password, plus a connection card and URL for each selected protocol, for example `sftp://username@host:port/eingang`. Both protocols use the same credentials and the same tenant inbox. Enter the shown server, port, username, password and directory separately if the scanner does not accept URLs. The password is deliberately omitted from the link. Compare the displayed persistent SSH host-key fingerprint when your scanner supports host verification. Scanner credentials are encrypted at rest and only visible to tenant owners. Password rotation, disabling the account, changing protocol or disabling FTP on the server revokes existing transfers at the next write/finalization.

**FTP is optional** for scanners that cannot use SFTP. The owner must select FTP and explicitly acknowledge unencrypted transmission; SFTP remains the default. FTP sends passwords/documents in cleartext and belongs on a trusted LAN or VPN. The server administrator can disallow it globally. Use passive FTP and binary transfer mode. Default published ports are **2222/TCP SFTP**, **2121/TCP FTP**, and **30000–30009/TCP passive FTP data**. Set `SCANNER_BIND`/firewall rules to the intended scanner network; normal HTTP reverse proxies do not forward these protocols. For port 21/22 scanners, change the external `FTP_PORT`/`SFTP_PORT` mappings. The UI's scanner server settings change the displayed public address/ports, not Docker's listeners or firewall. Behind NAT, forward both the FTP control and passive data ports, and set `FTP_PASV_ADDRESS` if the advertised IPv4 differs from the scanner hostname.

The scanner process checks saved account settings every five seconds and starts only the SFTP/FTP listeners required by tenants with active owners. In Host network mode these are actual host listeners: activating a protocol opens its configured TCP listener automatically, without recreating the container. Disabling the last eligible account for a protocol closes its listener; other tenants keep their required listeners. FTP passive data ports are opened on demand during transfers. Port conflicts are reported and retried rather than stopping the scanner service. The connection card shows listener status and has a refresh button. This verifies the running listener, not reachability from the scanner network. Host firewall rules and router forwarding remain separately managed; the container has no privileges to change them.

Accounts are virtual and upload-only: no shell, command execution, port forwarding, archived-document downloads, path traversal, anonymous access or cross-tenant access. Uploads are bounded by the normal file-size limit and staged separately. An interrupted transfer is never imported. Only a fully received, synced, format-checked and checksum-verified file is atomically published into that tenant's inbox. Existing input names are never overwritten; configure unique scanner filenames. Staging lives in `scanner_state`, so allow sufficient local disk space even when documents use NAS storage. The service bounds connections and login attempts; completed uploads cannot exceed the configured per-file limit, while tenant archive quota is enforced again during import.

**Pending-file listings:** FileZilla and other FTP/SFTP clients can list completed uploads still present in their document space's scanner inbox. FTP supports `LIST`, `NLST`, `MLSD`/`MLST`, size and modification-time queries; SFTP returns file names, sizes and timestamps. `/eingang` is the recommended directory; root-level uploads/listings remain compatible. Refresh the client's remote directory after uploading. Incomplete transfers, hidden staging files, unsupported names, symlinks, empty files and subdirectories are excluded. After successful import, the source disappears when deleted or moved to `verarbeitet`; failed or duplicate source files remain visible for diagnosis. Neither archived originals nor `verarbeitet` are exposed. Scanner accounts still cannot download, delete, rename or overwrite files. Every listing and metadata query verifies the active account generation and NAS storage, so rotated/disabled sessions cannot keep browsing and storage outages report errors instead of an empty local fallback.

Activating network input also enables that tenant's folder integration. The combined dialog controls deletion/archiving, settle delay and destination folder; existing values are retained. The legacy scanner API uses deletion and a five-second delay when no folder settings exist. Existing folder settings are preserved, including optional processed-source archiving. Disabling the scanner account prevents new network uploads; the folder integration can continue processing already completed files. Its settings and retained error files remain under **Integrationen → Scanner-Importordner**.

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
| Manager | Also manage permitted folders, rules and lower-role members, and permanently delete editable trashed documents |
| Owner | Also configure integrations, access lists, workflows, backups, activity history and membership roles |
| Server administrator | Global settings, quotas, domains, account suspension and external authentication; document access still requires tenant membership |

Folder and document restrictions both apply; an explicit document grant does not bypass a restricted folder. Owners retain access. Search, statistics, previews, downloads, version history and review queues observe these restrictions. Removing a tenant member also removes their individual grants.

At **Dokument → Versionen**, upload a new original or restore a previous one as a new version. Previous files remain unchanged. OCR and enabled automatic AI run again. The new version resets extracted metadata, payment status and approval; title/tags remain. Trash and historical versions continue to count against quota.

Enable optional workflows at **Raumeinstellungen → Prüfabläufe**. A different eligible editor with document access decides on the current version; the requester/uploader cannot approve it themselves. Changes supersede pending reviews and reset approval while retaining history. The approval status is an organizational marker, not a download or payment lock.

Set up a TOTP authenticator under **Konto → Zwei-Faktor-Anmeldung**, confirm a valid code and save the ten one-use recovery codes separately. They are shown only when generated. Activation/deactivation revokes existing sessions. The DMS factor also applies to LDAP/OIDC logins for that account.

## Automatic naming and folder rules

Under **Automatische Regeln**, managers/owners can define a condition and either a destination folder, a filename template, or both. **Alle Dokumente** matches every document; other conditions match text, supplier, document type, title or filename (case-insensitive, including the current version's original import name).

Choose a **Namensschema** preset in the rule dialog, such as **Absender - Jahr - Monat - Tag** → `Example GmbH - 2026 - 10 - 13.pdf`. Other presets combine the import date, sender and document type, or year/month and sender. You can edit any preset to create your own template. Templates have **no extension**, for example `{sender} - {year} - {month} - {day}` or `{date}_{supplier}_{doc_type}`. The dialog offers placeholder buttons and a preview explicitly using sample data. Selecting a preset does not change the rule's matching condition; choose **Alle Dokumente** to apply it to every document.

**Nested folders from naming rules:** Select an **Ordnerstruktur** preset, or enter an **Ordner-Vorlage** such as `Invoices/{year}/{sender}`. Folder templates use the same metadata placeholders as filenames. Missing folders are created and existing tenant-local folders are reused. The optional **Zielordner / Basisordner** makes the generated path relative to that folder; without a base it starts at the document space's root. You may instead put the path before the filename, e.g. `Invoices/{year}/{sender}/{date} - {doc_type}` in the filename field, leaving the separate folder template empty. The server stores its folder and filename portions separately. A rule can generate folders without renaming files.

For example, a document imported on February 3, 2026 with sender `Example GmbH` and type `Rechnung` becomes `Invoices → 2026 → Example GmbH → 2026-02-03 - Rechnung.pdf`. Year/month/day refer to the **UTC import date**, not the invoice date. Missing metadata delays the action without creating incomplete paths. Automatic OCR/AI processing and **Auf bestehende Dokumente anwenden** both apply folder templates. Explicit manual folder selection during metadata editing remains authoritative; use the apply action to reconsider filing after a manual metadata correction.

Open **Ordner** and then a folder to browse its children; breadcrumbs navigate back up. Folder cards count visible documents in the whole subtree, while the document list shows the selected folder's direct documents. **Unterordner erstellen** also allows manual creation. Restrictions on every ancestor remain effective for both reading and editing descendants, including after permission changes. Unattended dynamic rules use the configuring member's current permissions; rules configured by a disabled account or a member no longer holding manager/owner rights pause their dynamic actions. Restored rules belong to the restoring owner. Nested folder parents and templates are retained in encrypted tenant backups; old backups remain readable.

Paths are logical DMS folders; originals and immutable versions stay in their tenant/document UUID archive directories on the NAS. Paths have at most eight levels and 700 characters. Absolute paths, traversal and empty components are rejected; metadata cannot introduce additional path levels. Long generated components are shortened with a stable hash to keep them distinct. Deleting a parent requires removing its children first. Schema migration `0010` preserves existing folders as roots and refuses a downgrade that would discard hierarchy or folder templates.

| Placeholder | Value |
| --- | --- |
| `{date}`, `{year}`, `{month}`, `{day}` | UTC import date (`YYYY-MM-DD`), four-digit year, two-digit month/day; these are not invoice dates |
| `{sender}`, `{supplier}` | Both use the same **Lieferant / Absender** field from AI or edited document metadata; not the mail's From header |
| `{doc_type}` | Document type from OCR/AI or edited metadata |
| `{original_name}` | Current version's original import filename without its last extension |
| `{title}` | Document title |
| `{due_date}` | Invoice due date (`YYYY-MM-DD`) |
| `{amount}` | Stored amount, without currency |
| `{id}`, `{version}` | Document ID and current version number |

Rules run after OCR, after successful AI processing/retries and for filenames after metadata edits. **Auf bestehende Dokumente anwenden** applies them to completed active documents you may edit. Lower priorities run first; the first matching folder action and the first usable filename action win independently. Disabled rules are skipped. A naming action with missing metadata waits; a lower-priority fallback may still supply a name. Changing a rule does not immediately rewrite existing documents.

Renaming updates the visible/download filename and records an audit event. Document titles, checksums, original version names and stored content remain intact. Path/control characters in metadata are sanitized, names fit a 255-byte UTF-8 limit, and conflicting active names within a tenant gain the document ID. Templates accept only the documented placeholders, with no code or expressions. Tenant backups include templates and current display names; older backups without these fields still restore.

## Document workspace tools

**Deletion and Trash:** Editors with document/folder edit access can use the trash icon in document lists or **Löschen** in document details. This moves the document to **Papierkorb**, where it remains recoverable and still counts against storage quota. Managers/owners with edit access can choose **Endgültig löschen** in Trash or document details and confirm. Permanent deletion requires a trashed document and cannot be undone. Its durable background job removes the archive directory with all versions, OCR/metadata, notes, PDF annotations, reviews, document grants, contracts and sharing tokens. Restoration, viewing and editing are blocked once deletion has been confirmed. Storage failures retain the job and retry automatically; quota is released after cleanup completes. The trash list displays progress and refreshes automatically while deletions are pending. Symlinked archive directories are rejected. Audit entries and import receipts remain, preventing automatic reimport from previously consumed mail/scans. Original mail/scanner sources and separately retained backups/NAS snapshots are unaffected. Pending CalDAV event removal is retained and retried on the next successful calendar synchronization, even after document metadata is gone. New tenant backup exports exclude documents already marked for permanent deletion.

**Duplikate:** Upload/scanner imports reject a checksum already present in an active document's current or historical versions within the same tenant. The message does not reveal another document's ID/name. Scanner duplicate sources remain in the input directory. The duplicate view compares only documents the current member can read: up to the latest 200 active documents, at most 100 pairs. Word-set similarity over the first 50,000 OCR characters (minimum 12 distinct words and 100 characters, threshold 85%) is a review hint, not proof of identity. Invoice numbers/amounts are not removed; nothing is automatically merged or deleted.

**Sammelbearbeitung:** On All documents, Inbox or Trash, select documents using the checkboxes and choose **Auswahl bearbeiten**. Tags are replaced, not appended. Folder/document edit permissions and processing states are checked for the entire selection before any changes are saved. A forbidden item rejects the whole batch. Metadata changes reset review status; reprocessing triggers OCR and any enabled automatic AI again.

**Vertrag & Fristen:** Add contract data from the document details. Store partner, optional start, end date, notice period and reminder lead time in calendar days. The cancellation deadline is end date minus notice days; reminders start that many reminder days earlier. Active reminders appear in the contract view and dashboard. They do not renew contracts, cancel anything, send emails or synchronize contract reminders via CalDAV; existing invoice CalDAV remains available.

**Freigabelinks:** Managers/owners with edit access can create a link for the current document version, valid for 1–90 days. Optional passwords require at least 12 characters and are stored as Argon2 hashes. The high-entropy URL token is returned once and only its hash is stored. Password unlocking is rate limited and uses a separate, one-hour HttpOnly cookie. Each access rechecks expiry, revocation, trash status, creator activity, tenant role and current document/folder rights. A new version is never silently exposed by an old link. Downloads include only that version, not internal notes/annotations. Use HTTPS and protect link URLs from proxy access logs; anyone possessing the link (and optional password) can download it. The link is a download authorization, not DRM.

**Notizen / PDF markieren:** Editors with document edit access add notes; only the author or tenant owner can edit/remove them. PDF highlights are rectangles with optional comments and color, stored against a particular version/page. Select historical PDF versions in the markup view. Highlights are displayed over a locally rendered preview and are not embedded in or exported with the original. **They are not redactions.** Notes/annotations follow existing document/folder read permissions and are included in tenant backups.

**Systemzustand:** Server admins see database connectivity, worker heartbeat, OCR availability, filesystem free space, processing/AI queues, scanner import errors and integration status. Storage figures describe the backing filesystem, not just the DMS allocation. The backup timestamp reports the last successful tenant export; external MariaDB/NAS backup jobs and safe storage of downloaded exports are not monitored.

## OCR and AI

Local OCR, search, basic invoice extraction and filing rules work without an external AI provider. PDF extraction is limited to 100 pages; image-PDF OCR and TIFF processing to 50 pages. Unreadable or textless documents retain their original and show an OCR warning; they can optionally use the whole-document AI fallback described below. Originals are not rewritten into OCR PDFs.

New tenants have AI disabled until the owner configures a provider and consent. The integration dialog offers automatic processing, requiring separate automatic-transfer consent. Existing configurations without that consent remain manual. Manual mode lets the owner edit a minimized preview and explicitly approve the exact text before transmission.

For ordinary text-based AI extraction, before either provider is contacted, the server masks recognized email addresses, URLs, common IBAN/phone formats and labeled account/tax/customer identifiers, then limits the OCR excerpt to 1,000–10,000 characters (default 10,000). Original file containers, filenames and DMS user/tenant identifiers are not included in the AI payload. If the whole-document fallback is enabled, complete visible page content is transmitted as images instead of a minimized text excerpt. Pattern masking is **not guaranteed anonymization**: names, addresses, sensitive context or OCR errors may remain. In automatic mode there is no individual preview approval. The server administrator can block all external AI transfers globally.

An AI outage leaves the original accessible and any successful local OCR searchable, with an **AI pending / KI ausstehend** status. Retries back off up to one hour; disabling the integration or globally blocking AI prevents further transfers. AI-derived metadata still requires human verification.

### Whole-document fallback after OCR failure

Under **Integrationen → KI-Metadaten**, enable **Wenn OCR scheitert: sämtliche Dokumentseiten automatisch an die KI übertragen**. This requires automatic mode and both consent controls; existing tenant configurations leave it disabled. It runs automatically when local OCR fails or returns no non-whitespace text. A difficult but nonempty OCR result does not by itself trigger image transfer.

The DMS renders every PDF page or image/TIFF frame locally as a metadata-free JPEG, with a maximum dimension of 2,000 pixels. The complete visible content, including names, signatures and addresses, is sent to the selected provider. **Image content is not automatically redacted.** Original PDF containers, filenames, EXIF metadata and account/tenant identifiers stay local. Limits are 50 pages and 20 MB of generated JPEG data; oversized documents are not silently truncated. An unreadable/encrypted PDF cannot be repaired by this fallback. The selected model must support image inputs.

The gateway uses Codex's [official image input](https://learn.chatgpt.com/docs/app-server#turns); API mode uses [Responses image inputs](https://developers.openai.com/api/docs/guides/images-vision). Whole-document transfers have a separate audit event. Global AI blocking, tenant consent, Codex tenant authorization and disabled integrations apply equally to images and text. The result populates document metadata; it does not create a replacement full-text transcription, so failed local OCR still limits full-text search. Provider outages use the existing retry schedule. Reprocessing restarts local OCR.

### Codex with a ChatGPT subscription

1. Under **Serveradministration → Codex**, connect your ChatGPT account using the official device-login page linked by the application. ChatGPT passwords are never entered into the DMS. Enable device login in your account/workspace if required.
2. Allow the intended tenants to use the connected subscription in the same admin panel.
3. Under **Integrationen → KI-Metadaten**, select **Codex (ChatGPT-Abonnement)**, activate the integration and explicitly consent to the desired manual/automatic mode.

The gateway uses the official Codex App Server over local stdio, pinned to CLI **0.162.1**. Each document gets a new ephemeral thread, isolated temporary working directory and validated output schema. Shell/tools, browsing, apps, plugins and further agents are disabled. The gateway receives minimized text or, when explicitly enabled after OCR failure, inline document page images. It has no DMS database/document-volume mount and cannot read other documents. Account access conditions and usage limits apply; there is no automatic paid-API fallback.

**Account quota display:** Server administrators see the provider-reported remaining/used percentages, window durations, reset times and additional credits (when supplied) in **Serveradministration → Codex**. Values come from the official `account/rateLimits/read` endpoint, refresh approximately every minute and include usage by other Codex clients and all authorized tenants. Missing values remain unknown; a failed quota read does not disconnect the account or block document extraction. These figures are not a document/token allowance. Tenant members cannot access account quota, email or plan details. See the [official rate-limit API](https://learn.chatgpt.com/docs/app-server#rate-limits-tokenscredits).

The `codex_auth` volume persists sensitive account tokens, owned by UID/GID 10002. Protect and back it up separately; disconnect via the admin panel. For login/data-handling details see [OpenAI's Codex authentication documentation](https://developers.openai.com/codex/auth/) and [App Server documentation](https://developers.openai.com/codex/app-server/). Ephemeral local threads do not guarantee zero provider-side retention.

### OpenAI API

The alternative integration uses your API key and an API-compatible endpoint supporting Responses with Structured Outputs. Requests set `store: false` and use the same minimization and consent controls. API access/billing is separate from the subscription gateway. See [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs). Provider/workspace data controls still apply; `store: false` is not a blanket guarantee of zero retention.

## Other integrations

- **IMAP:** Add multiple independently named mailboxes per document space under **Integrationen → E-Mail-Import → Postfach hinzufügen**. Each connection has its own credentials, IMAP folder, attachment filter, automatic polling switch, last result and persistent message receipts. Existing connections and their import history are preserved automatically on upgrade. Pause a connection by clearing **Postfach automatisch prüfen**; this retains receipts. Removing it deletes its connection settings and receipts, while already imported documents stay in the archive. Owners alone manage mailboxes. TLS with certificate verification, password/app-password authentication, approximately five-minute polling. Imports supported attachments and optionally plain-text mail; UID/UIDVALIDITY receipts persist in the database per integration and mailbox identity, so completed messages are not fetched again after restarts. In **E-Mail-Import → E-Mail-Filter**, choose **Nur E-Mails mit PDF-Anhang** to import only PDF attachments detected from their bytes; filenames and declared MIME types alone are insufficient. Optional body import applies only to matching messages in this mode. Messages without PDFs are remembered for the PDF filter to avoid repeated downloads. Widening the filter allows previously excluded messages to be considered, while completed messages remain skipped. Failed imports are not marked complete and are retried; checksum duplicates are not stored again. Changing UIDVALIDITY creates a new mailbox epoch, with tenant document checksums preventing duplicate documents. The mailbox is read-only with `BODY.PEEK`; no deletion or outgoing email. OAuth mail login is not implemented. Invitations are copyable expiring links, not automatically sent email.
- **CalDAV:** Configure an existing HTTPS calendar collection. Approximately 15-minute polling creates/updates all-day due-date events and removes paid/trashed documents. Synchronization is DMS → calendar only; a dedicated calendar is recommended. Clean up the previous calendar when changing the URL.
- **Local accounts:** New local accounts always require a valid invitation. Public password-based sign-up is disabled, including installations that previously enabled it. Existing local accounts can still sign in. LDAP/OIDC account creation does not grant administrator rights or membership of existing document spaces; tenant access requires a separate invitation.
- **LDAP/Microsoft AD:** LDAPS or StartTLS with verified certificates, base DN, bind credentials and escaped email search filter; default `(mail={email})`. The directory must supply `mail`. Mount private CA files if needed. Successful directory authentication automatically creates a DMS account without an invitation. Restrict eligible users through the directory search filter and directory permissions. Tenant invitations/roles remain locally managed; no automatic group synchronization or email-only conversion of existing local accounts.
- **OIDC:** Configure discovery URL, client ID/secret and exact `<HTTPS-BASE-URL>/api/auth/oidc/callback`. Uses state, nonce, signature/claim checks and PKCE; requires `openid profile email` and an email address. Email verification is optional and disabled by default; enable **Bestätigte E-Mail-Adresse verlangen** to require `email_verified=true`. Successful OIDC authentication automatically creates a DMS account without an invitation. Restrict eligible users through the provider's application access policies. Link an existing account while signed in locally. Use **Administration → Verzeichnis & Single Sign-on → OpenID Connect** to run **Konfiguration prüfen** on the current form values without saving, then save/enable the configuration and run **Anmeldung testen**. The latter runs a real authorization-code flow with the saved settings and checks the ID token and account eligibility without creating/linking accounts or replacing the administrator's DMS session. Results expire after ten minutes. Use the same public domain throughout; secure cookies require HTTPS. Neither tokens nor the client secret appear in the report.

  **Authentik:** Copy the application's discovery URL (usually `https://<authentik>/application/o/<application-slug>/.well-known/openid-configuration`), configure the exact callback URI and select a signing key in the provider. Include the `openid`, `profile` and `email` scope mappings and the email claim in the ID token. Authentik 2025.10+ returns `email_verified=false` in its default email mapping; this works with the DMS default. If you enable the optional verified-email requirement, configure actual email verification and a corresponding scope mapping using [Authentik's email verification guide](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/verify-email-address/). Account linking still requires a matching local session, even when email verification is disabled.

## Backups and restore

Tenant owners can download a password-encrypted `.dmsbackup` under **Raumeinstellungen**. It includes all file versions, OCR text, metadata, folders, rules, contracts, notes, version-bound PDF annotations and archived permissions/reviews. External sharing tokens/passwords are never exported. AES-256-GCM provides encryption and integrity protection; Scrypt derives the key. There is no recovery without the password. The default 250 MB limit suits smaller tenant archives.

Restoration creates a new tenant owned only by the restoring user. Previous users must be reinvited, permissions reapplied and approvals renewed. Archived rights/reviews and original note/annotation authors are available for inspection. Restored notes and annotations are assigned to the restoring owner, without creating former accounts. External links are not recreated. Account passwords, MFA secrets and integration credentials are not imported; restoration does not automatically send documents to AI.

For full recovery, coordinate MariaDB, document/NAS storage, scanner input, `.env`/`SECRET_KEY`/`STORAGE_SERVICE_TOKEN`, `storage_state`, `scanner_state` (including the SSH host key), and Codex auth backups. A database dump without files, or files without metadata, is incomplete. Store backups separately and protect their secrets. [Restore guide](docs/RESTORE.md).

```bash
# Check every stored document version against its SHA-256 checksum.
docker compose -f docker-compose.yml exec app python scripts/check_integrity.py
# Inspect health and logs.
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml logs --tail=100 app
```

`scripts/backup_dev.py` is specifically for the **local source-build development stack** (`compose.yaml` + `compose.dev.yaml`) and stops the app, scanner and gateway briefly while keeping the NAS helper available. It is not an external-MariaDB backup tool. It archives the active storage roots, storage configuration and scanner host key. Pause any direct folder/NAS writers during coordinated backups.

## Development and validation

```bash
# Local source builds and a private development database:
python3 scripts/init_env.py  # fresh checkout only; existing .env is preserved
mkdir -p consume
sudo chown 10001:10001 consume
# One-time preparation for mount propagation from the NAS manager:
sudo python3 scripts/prepare_storage.py /srv/dms-system/nas
docker compose -f compose.yaml -f compose.dev.yaml up -d --build

# Isolated SQLite tests; real tenant data is untouched.
docker run --rm --entrypoint python -v "$PWD:/app:ro" \
  dms-archiv-app -m pytest tests -q -p no:cacheprovider

# Development-stack backup, outside the repository:
python3 scripts/backup_dev.py /srv/backups/dms-YYYY-MM-DD
```

The test suite covers tenant separation, OCR, versions, access lists, review decisions, MFA, scanner cleanup, genuine SFTP/passive FTP uploads, interrupted/rotated credentials, NAS fail-closed behavior, verified migration, encrypted restore, AI consent/minimization, whole-document fallback gates, bulk atomicity, contracts, share revocation/passwords/version pinning, annotations, note ownership and mocked external integrations. CI additionally uses MariaDB 11.4. External MariaDB/NAS, actual identity providers, mail/calendars and live AI accounts need validation against the intended deployment.

This implementation targets one application container rather than a horizontally scaled cluster. Search uses SQL substring matching, without a dedicated index or semantic search. It does not implement WORM storage, tamper-proof audit archives, retention automation, email password reset, office previews, antivirus quarantine, automatic camera perspective correction or realtime notifications. Original retention and an activity log alone do not constitute a legal compliance/revision-safety guarantee.
