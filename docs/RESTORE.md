# Restore guide

## Full-instance recovery

A complete backup needs the MariaDB database, all document versions, scanner input, deployment configuration including `SECRET_KEY`, the private Codex authentication volume, `storage_state` and `scanner_state` (persistent SSH host key), and `STORAGE_SERVICE_TOKEN`. Backups contain confidential documents and credentials; protect them and keep a copy outside the original server/NAS.

For external MariaDB and NAS storage, use their backup/snapshot tooling and coordinate database and filesystem consistency. The development helper `scripts/backup_dev.py` applies only to the source-build stack (`compose.yaml` + `compose.dev.yaml`). Its files are `database.sql`, `documents.tar`, `consume.tar`, `codex_auth.tar`, `storage_state.tar`, `scanner_state.tar`, `configuration.tar` and `manifest.json`.

A full restore replaces data. First test on a separate instance with its own database, volumes, scanner path and port:

1. Compare each dump/archive's SHA-256 with `manifest.json`, if using the development helper.
2. Restore configuration privately. Reuse the saved `SECRET_KEY` so integration/MFA secrets can be decrypted. Set `.env` permissions to 0600. Use the image version corresponding to the backup; do not assume a newer database can run an older image.
3. Choose a different Compose project name, port and persistent storage. Set a separate `CONSUME_PATH` and never allow a real scanner to write to the test restore input. For host networking, preserve the `docker-compose.host.yml` override and choose distinct `APP_PORT`, `SFTP_PORT`, `FTP_PORT`, passive FTP range, `CODEX_PORT`, `STORAGE_PORT` and optional `DB_PORT` for the recovery test.
4. Start only the selected restore database and import the SQL dump. For a local-database **published-image restore instance**:

   ```bash
   docker compose -p dms-restore -f docker-compose.yml -f docker-compose.db.yml up -d db
   docker compose -p dms-restore -f docker-compose.yml -f docker-compose.db.yml exec -T db sh -c 'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" mariadb -uroot dms' < /PATH/TO/BACKUP/database.sql
   ```

   For an external database, import into a separate database through its own administration tools and point `DATABASE_URL` to that database.

5. Restore document files into the selected new volume/mount, retaining the entire version directory structure. These commands apply only to the separate restore instance:

   ```bash
   docker compose -p dms-restore -f docker-compose.yml -f docker-compose.db.yml run --rm --no-deps --user 0 --entrypoint tar app -C /data/documents -xf - < /PATH/TO/BACKUP/documents.tar
   docker compose -p dms-restore -f docker-compose.yml -f docker-compose.db.yml run --rm --no-deps --user 0 --entrypoint chown app -R 10001:10001 /data/documents
   ```

   Restore `consume.tar` into its separate scanner-input mount and apply UID/GID 10001 permissions. The development source-build restore instead uses `-f compose.yaml -f compose.dev.yaml` consistently for every command.

   For a **local-mode restore test**, keep the new `storage_state` empty so the helper initializes local mode, and restore documents/consume into the new local mounts. Do not restore an active NAS pointer into a test that must not touch the real NAS. Use a separate `NAS_MOUNT_PATH` prepared with `scripts/prepare_storage.py` and different SFTP/FTP ports; disable scanner integrations before starting the restored scanner service.

   On the final recovery instance, `storage_state.tar` contains the encrypted NAS connection and active mount location. Preserve `STORAGE_SERVICE_TOKEN`, restore the state volume with UID/GID 10001, prepare the shared mount parent, and start `storage` before the application. The helper reconstructs a missing active mount. Restore documents/consume into the **active NAS roots**, not blindly into the unused local volume. Always verify that the destination is the intended recovery NAS, and keep writers stopped. Restore `scanner_state.tar` with UID/GID 10001 to preserve the SSH host key; a new key otherwise requires scanner trust to be updated. Incomplete `.part` transfers are discarded by the scanner on startup, while completed sources are in `consume`.

   `codex_auth.tar` contains sensitive ChatGPT tokens. For an isolated restore test, start Codex with an empty dedicated volume. On the final recovery instance, restore it only into that instance's `codex_auth` volume and assign UID/GID 10002. Expired tokens may require a new login.

6. **Before starting the app**, disable external integrations and clear sessions/challenges in the restored database:

   ```sql
   UPDATE integrations SET enabled = 0;
   DELETE FROM sessions;
   DELETE FROM mfa_challenges;
   ```

7. Start the selected restore instance. Check sign-in, MFA/recovery codes, memberships, access restrictions, document previews, every version and OCR search. Run the checksum tool:

   ```bash
   docker compose -p dms-restore -f docker-compose.yml -f docker-compose.db.yml exec app python scripts/check_integrity.py
   ```

8. After verification, switch the intended deployment to the recovered instance and explicitly reactivate the desired integrations. Preserve the original backup until the recovery is accepted.

Do not use `docker compose down -v` on a deployment whose data you need to preserve. Replacing an image without restoring matching database/files/configuration is not a complete rollback.

## Encrypted tenant archives

Under **Raumeinstellungen**, a tenant owner can export a `.dmsbackup` protected by a password of at least 12 characters. It contains all versions and metadata for that tenant, plus folders, rules and archived access/review information. It does not include account passwords, MFA secrets or integration credentials. If processing is active, retry export after it finishes.

**Sicherung wiederherstellen** always creates a new document space. Existing spaces are not overwritten. An incorrect password, tampered file, invalid manifest or mismatched document checksum aborts restoration and removes incomplete restored data.

After restoring, download sample current and historical versions and check OCR search and filing rules. Reinvite former members and reapply permissions; the archived permission/review information is available for inspection under **Archivierte Rechte und Prüfungen ansehen**. Approvals must be renewed. Integrations remain inactive until explicitly configured; restoration does not automatically transmit documents to AI.

All restored versions count against quota. The web archive limit defaults to 250 MB (`MAX_TENANT_BACKUP_MB`); larger installations require coordinated full backups. Store the archive password separately: there is no password recovery. A tenant archive complements full-instance backups and does not replace them.
