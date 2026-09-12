# Authentication

## Components

| Component | Responsibility |
| --- | --- |
| Setup endpoint | Creates the first administrator after validating a one-time bootstrap token |
| Users table | Stores username, role, scrypt parameters, salt, and password hash |
| Sessions table | Stores only SHA-256 digests of random session and CSRF tokens |
| Session cookie | Carries the opaque session token as HttpOnly and SameSite=Strict |
| CSRF cookie and header | Uses the double-submit pattern plus a server-side token digest |
| Route guard | Requires an unexpired administrator session for protected routes |
| Audit table | Records security-relevant actions without secret values |

## First-run flow

1. The installer creates a random 256-bit bootstrap token using Python's secrets module.
2. The token is written to /var/lib/homelab-control-center/bootstrap-token with root:hcc ownership and mode 0640.
3. The browser submits the token, desired username, and password to POST /api/setup.
4. The server compares the submitted token with hmac.compare_digest.
5. The password is hashed with scrypt using a fresh 128-bit salt.
6. The administrator is inserted into SQLite.
7. The bootstrap-token file is deleted so setup cannot be repeated.
8. A new authenticated session is returned.

There is no public registration route. If an administrator already exists, the setup endpoint returns a conflict response even if a token file is present.

## Login flow

~~~mermaid
sequenceDiagram
    participant Browser
    participant Server
    participant SQLite
    Browser->>Server: POST /api/login
    Server->>SQLite: Load password record
    Server->>Server: Recompute scrypt and constant-time compare
    Server->>SQLite: Store session and CSRF digests
    Server-->>Browser: HttpOnly session cookie + CSRF cookie
    Browser->>Server: Protected request + cookies
    Server->>SQLite: Hash session token and load unexpired session
    Server-->>Browser: JSON response
~~~

Login failures are deliberately generic. Attempts are rate limited per source address in memory.

## Password handling

Passwords must be at least 12 characters and at most 256 UTF-8 characters. They are never logged or stored in plaintext.

The stored format records the algorithm parameters, random salt, and derived key. Version 0.1.0 uses:

- scrypt N = 32768
- r = 8
- p = 1
- 32-byte derived key
- 16-byte random salt

Verification uses hmac.compare_digest.

## Session handling

A session token is generated with secrets.token_urlsafe(32). The browser receives the plaintext value only in the hcc_session cookie. SQLite receives SHA-256(token), never the token.

The cookie has:

- HttpOnly
- SameSite=Strict
- Path=/
- Secure when secure_cookies is enabled

Sessions expire after the configured number of hours. Logout deletes the server-side session and expires both cookies.

## CSRF handling

A separate random token is placed in a non-HttpOnly hcc_csrf cookie so the same-origin JavaScript can copy it into X-CSRF-Token. State-changing routes require:

- a valid session
- the CSRF cookie
- the X-CSRF-Token header
- equality between cookie and header
- a digest matching the active session record

Cross-origin requests cannot read the CSRF cookie, and SameSite=Strict prevents normal cross-site cookie sending.

## Remote credentials

The application never accepts or stores remote SSH passwords.

The installer generates a dedicated Ed25519 key owned by hcc with mode 0600. Only its public half is copied to remote monitoring accounts. known_hosts is populated only after the administrator probes and explicitly trusts the displayed fingerprint.

The private key is never sent to the browser, returned by an API, placed in logs, or committed to Git.

## Update credentials

Public GitHub raw files and the public commits API are used without a GitHub token. Runtime updates therefore store no repository credential. The installer resolves a commit SHA first and downloads all payload files from that immutable ref.
