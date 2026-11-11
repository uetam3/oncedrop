# Security policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's *Report a vulnerability* feature:
<https://github.com/uetam3/oncedrop/security/advisories/new>

Do not open a public issue for a security problem. You can expect an acknowledgement within a few days.

## Scope

In scope: the encryption of shares, the local admin panel (authentication, CSRF, DNS rebinding), the public receiver, the tunnel handling and the embedded `cloudflared` handling.

Out of scope:

- The security of the recipient's phone and of the apps the file is shared to.
- Someone capturing the QR code from your screen.
- Vulnerabilities in the tunnel providers (Cloudflare, localhost.run).
