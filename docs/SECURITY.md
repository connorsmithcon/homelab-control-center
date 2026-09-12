# Security model

## Intended deployment

The default listener is 0.0.0.0:8088 so it is reachable on a homelab LAN. Plain HTTP does not protect credentials from a hostile network. Use one of these deployment patterns:

- a trusted isolated management LAN
- Tailscale or another authenticated private network
- a TLS reverse proxy, with secure_cookies changed to true

Never port-forward 8088 from the public internet.

## Trust boundaries

- Anyone with an administrator session can view logs and control permitted services.
- The hcc account can read its SQLite database and dedicated SSH private key.
- The local action broker runs as root but exposes only fixed allowlisted actions.
- A remote SSH account has exactly the access granted on that remote host.
- GitHub is trusted as the source distribution channel during install and update.

## Defensive controls

- standard-library-only runtime
- no shell=True command execution
- fixed command construction and strict identifier validation
- 64 KiB request-body limit
- bounded subprocess output and timeouts
- session and CSRF tokens hashed in SQLite
- rate-limited login attempts
- constant-time secret comparisons
- explicit SSH host-key trust
- browser security headers and same-origin policy
- secret-free security audit records
- systemd filesystem and kernel hardening for the web service
- Unix socket authorization between web service and root broker
- immutable version-plus-commit release directories
- SHA-256 payload verification

## Known limitations in 0.1.0

- The built-in HTTP server does not provide TLS. Put it behind TLS or use a private encrypted network.
- Login rate limiting is in memory and resets when the service restarts.
- There is one administrator role and no per-node role delegation.
- The application does not encrypt its SQLite database at rest. It stores password and token hashes, but node addresses and audit metadata remain readable to root and hcc.
- SSH host-key probing is trust on first use. Verify fingerprints through a second channel before trusting them.
- Remote privilege safety depends on the remote helper and account configuration.
- apt-get upgrade can restart services according to distribution package policy.

## Reporting security problems

Do not publish real passwords, session cookies, bootstrap tokens, private keys, internal hostnames, or private addresses in an issue. Reproduce problems with redacted data.
