# Database installation, backup and migration

The installer runs an idempotent initial schema/bootstrap automatically. For an existing local PostgreSQL or MySQL server, create a **dedicated empty database and restricted application user**, then set `DATABASE_URL` before starting the app. Never point tests at an existing application database.

```text
postgresql+psycopg://USER:PASSWORD@HOST:5432/identity_lab
mysql+pymysql://USER:PASSWORD@HOST:3306/identity_lab?charset=utf8mb4
sqlite:///./data/lab.db
```

URL-encode special characters in database credentials. For PostgreSQL TLS, append `?sslmode=verify-full&sslrootcert=/path/to/ca.pem`. MySQL custom TLS connection settings are not exposed in this release; use the isolated Docker network or extend the driver configuration before remote deployment. The database must be PostgreSQL, MySQL or SQLite; “any local DB” does not mean arbitrary JDBC/Oracle/SQL Server compatibility.

## Schema and data commands

Run from the project root with backend dependencies installed and your target `DATABASE_URL` configured:

```sh
python -m backend.manage migrate
python -m backend.manage seed
python -m scripts.db_tools schema --dialect postgres --file schema-postgres.sql
python -m scripts.db_tools schema --dialect mysql --file schema-mysql.sql
python -m scripts.db_tools check
```

`migrate` creates missing tables; it is the initial release bootstrap, **not a versioned upgrade migration system**. This release uses a portable typed JSON record store (`lab_records`) instead of the normalized multi-table schema proposed in the master brief. See the architecture/coverage documents for concurrency and foreign-key limitations. Upgrades that alter the schema will require explicit migration scripts before release.

## Encrypted backups

Stop the app (leave its database running) before backup for a stable maintenance snapshot. Generate a key using `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Save the key in a private password manager or separate protected file. Set it in the `LAB_BACKUP_KEY` environment variable; do not paste it into shell history or commit it.

```sh
python -m scripts.db_tools backup --file lab-backup.enc
```

Backups include hashed credentials and personal synthetic profiles and are encrypted with authenticated Fernet encryption. The tool refuses to overwrite existing backup files. Losing the key makes a backup unrecoverable.

## Move PostgreSQL ↔ MySQL

1. Stop the source application and keep the source database/volume intact.
2. Create an encrypted backup and run `check`; save the record counts.
3. Prepare an empty destination database. Do **not** start the application yet, because startup seeds an empty store.
4. Change only the maintenance terminal's `DATABASE_URL` to the destination. Keep the source configuration available for rollback.
5. Set the original `LAB_BACKUP_KEY`, then run:

```sh
python -m scripts.db_tools restore --file lab-backup.enc
python -m scripts.db_tools check
```

6. Verify counts and sign-in, cross-protocol reads, protocol states, roles and audit data. All sessions and OAuth tokens are revoked on restore; obtain fresh tokens.
7. Configure the app to use the destination and start it. Keep the source backup until acceptance testing is complete.
8. To roll back before new writes, stop the destination app and restart using the original connection/volume. After new writes, rollback requires a new export/import plan; it must not silently discard destination changes.

Restore refuses a populated destination and commits all inserted records in one transaction. This is a maintenance-window procedure, not online replication. Client secret hashes and passwords remain valid; token/session revocation prevents copying active access across environments.

## Docker maintenance

The production image includes these scripts. For an isolated app container connected to the same Compose network, use `docker compose run --rm --no-deps app python -m scripts.db_tools check`. The application service must be stopped for backup/restore. To write a backup on the host, mount a dedicated folder and pass `LAB_BACKUP_KEY` as an environment variable inherited from your terminal. Do not place the key in command arguments, Dockerfiles or committed Compose files.

Before resetting data, back up and stop the lab. Reset is deliberately not a one-click admin action: deleting the selected Compose database volume erases the entire lab. Never remove volumes belonging to your existing Dechpoint installation.
