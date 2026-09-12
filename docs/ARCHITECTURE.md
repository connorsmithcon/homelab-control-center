# Architecture

Homelab Control Center is a single-host control plane. The web process runs without root. A separate, small broker owns the few local operations that require root.

~~~mermaid
flowchart TD
    B["Browser"] -->|"HTTP + session cookie"| W["Web service: hcc user"]
    W --> D["SQLite state"]
    W --> S["Local read-only collectors"]
    W --> R["SSH client"]
    W -->|"Unix socket: fixed actions"| A["Root action broker"]
    R --> N["Remote Linux nodes"]
~~~

## Components

### Web service

src/server.py serves the static interface and JSON API. It owns authentication, authorization, validation, audit recording, local read-only collection, and SSH collection.

It runs as the hcc system user. Its systemd sandbox makes the operating system read-only except for /var/lib/homelab-control-center and its runtime socket access.

### Browser interface

src/static contains plain HTML, CSS, and JavaScript. It is served from the same origin as the API. There is no build step, CDN, remote font, analytics script, or browser-side secret storage.

### SQLite state

The standard-library sqlite3 module stores:

- administrator records with password hashes
- session and CSRF hashes
- remote node connection metadata
- security audit events

The database does not store remote passwords, private API tokens, plaintext session tokens, or plaintext CSRF tokens.

### Local collectors

Read-only collectors use /proc, statvfs, systemctl, journalctl, and apt-get simulation. Commands are static, arguments are validated, shell execution is disabled, and output is capped.

### SSH collector

Remote nodes are reached with the dedicated Ed25519 key under /var/lib/homelab-control-center/.ssh. BatchMode, StrictHostKeyChecking, a dedicated known_hosts file, and timeouts are always enabled.

### Root action broker

src/actiond.py is started through a root-owned systemd socket. Only the hcc group can open that socket. The broker accepts a short JSON request, rejects unknown fields and actions, validates systemd unit names, and runs only:

- systemctl start, stop, or restart for a validated service unit
- apt-get update
- apt-get upgrade

It does not accept arbitrary commands or shell fragments.

## Request lifecycle

1. The browser requests a same-origin API route.
2. The web service validates the session cookie.
3. Mutating requests also require a matching CSRF cookie and X-CSRF-Token header.
4. Route-specific input is type checked and allowlisted.
5. Read operations use local collectors or SSH.
6. Privileged local operations are sent to the action broker.
7. The result is returned as JSON and a secret-free audit event is recorded.

## Release layout

Each installation is stored in a directory named with both the declared version and source commit. The current and previous symlinks select active and rollback releases. Updates do not modify an existing release directory.
