# Roadmap

The first release establishes a secure local control plane. Planned adapters will remain optional and separately permissioned.

## Near term

- Proxmox cluster inventory, VM state, tasks, and backup status
- Proxmox Backup Server datastore and job status
- TrueNAS pool, disk, snapshot, replication, and application status
- Docker and Podman container status without mounting an unrestricted Docker socket
- OPNsense gateway, CARP, interface, and service health
- AdGuard Home query and protection statistics
- Jellyfin, Plex, Sonarr, Radarr, Seerr, and SABnzbd health cards
- Prometheus-compatible metrics history and alert rules
- Notification destinations with explicit opt-in
- Read-only discovery import from a user-supplied inventory file

## Safety gates

Each adapter must document:

- exact ports
- exact API scopes
- whether a credential is needed
- how that credential is protected
- read-only versus mutating operations
- every command or endpoint it can invoke
- uninstall and credential-revocation steps
