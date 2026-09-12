# Operations and recovery

## Status and logs

~~~bash
homelabctl status
homelabctl logs
sudo homelabctl doctor
~~~

doctor checks required commands, Python syntax, configuration validity, filesystem ownership, service state, socket state, listener state, database writability, and SSH key permissions.

## Updates

~~~bash
sudo homelabctl update
~~~

Update resolves the latest main-branch commit, downloads the checksum manifest and payload from that exact commit, verifies every file, installs a new immutable release directory, changes the current symlink, and restarts services.

Configuration, accounts, sessions, nodes, SSH identity, and audit history remain under /etc and /var/lib and are not replaced.

## Rollback

~~~bash
sudo homelabctl rollback
~~~

Rollback swaps the current and previous release symlinks and restarts both services. It does not roll back the SQLite schema or configuration. Releases avoid destructive schema changes until a migration and backup framework is added.

## Resetting first-run setup

If no administrator exists and the token is missing:

~~~bash
sudo homelabctl bootstrap-token --rotate
~~~

If an administrator already exists, the command refuses to create a setup token. Account recovery is intentionally not a hidden backdoor in version 0.1.0.

## Uninstall

~~~bash
sudo homelabctl uninstall
~~~

This removes systemd units, command symlinks, and program releases. It preserves /etc/homelab-control-center and /var/lib/homelab-control-center.

To remove configuration, the database, audit history, and SSH keys too:

~~~bash
sudo homelabctl uninstall --purge
~~~

The purge operation is irreversible.

## Backup

Stop the web service or use SQLite's online backup command before copying state:

~~~bash
sudo systemctl stop homelab-control-center.service
sudo cp -a /etc/homelab-control-center /safe/backup/location/
sudo cp -a /var/lib/homelab-control-center /safe/backup/location/
sudo systemctl start homelab-control-center.service
~~~

Keep backups encrypted because they include the SSH private key and internal inventory.
