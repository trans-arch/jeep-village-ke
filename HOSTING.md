# Jeep Village pilot hosting

This source is prepared for a single Render Node web service with a 1 GB persistent disk. The Blueprint selects the paid 0.5 CPU / 512 MB compute plan (`0.5c-512mb`). Review the actual monthly compute and disk charges in Render before creating the service. No hosting subscription has been purchased by preparing these files.

1. Create/sign in to your Render account and connect your Git provider.
2. Put this source in a private Git repository. Include server.cjs, auth.cjs, package.json, render.yaml and public/. Never upload the Desktop database, credentials, runtime folder or real customer records to Git.
3. In Render choose New → Blueprint, select the repository and review render.yaml. Keep one instance and the persistent disk at /var/data.
4. Complete Render billing/service creation yourself after reviewing the recurring charges.
5. When deployed, open /health to check the service. Customers use /book; staff use /staff.
6. From the Render environment settings retrieve BOOTSTRAP_TOKEN. Visit /login, create the initial director with a unique 12+ character password and enter that token. Setup is permanently disabled once an account exists. Remove BOOTSTRAP_TOKEN after successful setup.
7. In Workers create each technician's worker record. In Staff accounts create individual technician accounts linked to those workers, plus secretary accounts as needed. Share initial passwords privately and have staff change them after signing in.
8. Test anonymous booking, secretary booking review/receipts, technician assignment isolation and director finance access before sharing links.

Permissions:
- Director: full records, finances, staff account creation/editing, password reset and disabling accounts.
- Secretary: bookings, job administration, read-only inventory, customer receipts. No supplier bills, payroll, stock purchase costs, business cash transactions or director reports.
- Technician: only assigned job registration/model, complaint, job date and progress. Can tick/untick completion only on those jobs. Cannot change assignments, pricing, collection or payments.

Sessions expire after 8 hours, passwords are salted scrypt hashes, cookies are HttpOnly/SameSite and Secure on Render. Login attempts and public booking submissions are rate limited. Account disabling or password reset revokes sessions. Public booking confirmation does not disclose other bookings.

Local Desktop: reopen the management shortcut. First visit creates the director account without a hosting token. Existing business records are retained. Old unauthenticated server processes must be stopped; the updated installer does this for processes launched from the app's bundled runtime.

The cloud database is separate from the Desktop database. This pilot starts with an empty cloud database; do not expect automatic synchronization. Importing existing records requires a separate controlled migration. Run one cloud instance: SQLite and in-process web routing are designed for a small pilot.

Backup: configure and verify backups of /var/data/jeep-village.db before relying on real financial data. Use SQLite's online backup interface, or stop the service and copy a checkpointed database. Render disk snapshots are an additional safeguard, not a substitute for an independently tested backup. Never copy only an active WAL-mode database file. Store backups privately and test restoration. JSON record exports do not include staff accounts and are not complete database backups.
