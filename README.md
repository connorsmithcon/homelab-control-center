# Homelab Control Center

A local-first web dashboard for checking Linux hosts, systemd services, journal logs, and operating-system updates from one place.

The project uses the Python standard library and a vanilla HTML/CSS/JavaScript interface. It has no npm or pip runtime packages, no telemetry, no ads, no analytics, and no required cloud account.

## What version 0.1.0 includes

- Responsive dark dashboard with Overview, Nodes, Services, Logs, Updates, Audit, and Settings pages
- Live CPU, memory, disk, load, uptime, network, and update summaries
- Local host monitoring plus agentless SSH monitoring for additional Linux hosts
- systemd service listing and start, stop, or restart controls
- journal log viewer with a fixed command allowlist
- A narrowly scoped root action broker for local service and package operations
- Local administrator account with scrypt password hashing
- Opaque sessions, hashed session records, HttpOnly cookies, and CSRF protection
- SSH host-key verification and SSH keys instead of saved remote passwords
- One-command install, update, rollback, doctor, audit, and uninstall operations
- Immutable release directories identified by version and Git commit
- Checksums for every installed payload file

## Requirements

The control host must have:

- A systemd-based Linux distribution
- Python 3.10 or newer
- curl
- OpenSSH client tools
- sha256sum
- Root access for installation

Ubuntu Server 22.04 or newer and Debian 12 or newer are the primary targets. Remote monitoring works with systemd-based Linux hosts reachable over SSH.

## Install

~~~bash
curl -fsSL https://raw.githubusercontent.com/connorsmithcon/homelab-control-center/main/install.sh | sudo bash
~~~

The installer prints the dashboard URL and one-time setup token. Open the URL, choose an administrator username and password, and enter that token.

The default listener is port 8088 on all interfaces. It is intended for a trusted LAN, a private VPN such as Tailscale, or a TLS reverse proxy. Do not expose port 8088 directly to the public internet.

## Audit before installing

~~~bash
curl -fsSLO https://raw.githubusercontent.com/connorsmithcon/homelab-control-center/main/install.sh
less install.sh
sudo bash install.sh --audit
sudo bash install.sh
~~~

Audit mode resolves the exact main-branch commit, downloads the manifest and payload into a temporary directory, verifies every SHA-256 checksum, prints what would be installed, and exits without changing the system.

Dry-run mode performs the same download and validation and then prints planned system changes:

~~~bash
sudo bash install.sh --dry-run
~~~

## Operations

~~~bash
sudo homelabctl update
sudo homelabctl rollback
sudo homelabctl doctor
sudo homelabctl uninstall
~~~

Other useful commands:

~~~bash
homelabctl status
homelabctl logs
sudo homelabctl bootstrap-token
sudo homelabctl node-key
~~~

Uninstall preserves configuration and state unless you explicitly run:

~~~bash
sudo homelabctl uninstall --purge
~~~

## Adding another host

1. Print the control center public key with sudo homelabctl node-key.
2. Add that public key to the remote monitoring account's authorized_keys file.
3. Make sure the remote account can read the system journal if log access is wanted.
4. In Nodes, select Add node, probe its SSH host key, verify the displayed fingerprint, and then trust and add it.
5. Install the optional remote helper only if service controls or update installation are wanted on that node.

Read [permissions](docs/PERMISSIONS.md) before granting remote privileges.

## Files and data

| Path | Purpose |
| --- | --- |
| /opt/homelab-control-center/releases | Immutable installed releases |
| /opt/homelab-control-center/current | Active release symlink |
| /opt/homelab-control-center/previous | Rollback release symlink |
| /etc/homelab-control-center/config.json | Non-secret service configuration |
| /var/lib/homelab-control-center/control-center.db | Users, hashed sessions, nodes, and audit events |
| /var/lib/homelab-control-center/.ssh | Remote-monitoring SSH key and known_hosts |
| /run/homelab-control-center/actions.sock | Local privileged-action socket |

Passwords, session cookies, bootstrap tokens, and private SSH keys are never committed to this repository.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Authentication](docs/AUTHENTICATION.md)
- [Security model](docs/SECURITY.md)
- [Ports and permissions](docs/PERMISSIONS.md)
- [Operations and recovery](docs/OPERATIONS.md)
- [Roadmap](docs/ROADMAP.md)

## Project status

Version 0.1.0 is the first usable release. It deliberately starts with a small command allowlist and Linux/systemd support. Proxmox, TrueNAS, Docker, OPNsense, AdGuard Home, and application-specific API integrations are planned as separate adapters rather than being granted broad host access.
