# Security Policy

## Supported versions

Security fixes are provided for the latest published minor release.

| Version | Supported |
|---|---|
| 0.1.x   | ✓ |

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Report vulnerabilities privately via GitHub's private vulnerability reporting:
go to the repository's **Security** tab and click **"Report a vulnerability"**.

> Note for maintainers: private vulnerability reporting must be enabled in the
> repository settings (Settings → Code security and analysis → Private
> vulnerability reporting) for the "Report a vulnerability" button to appear.

You can expect an acknowledgement **within 7 days**. We will keep you informed
of progress toward a fix and coordinate disclosure timing with you.

## Scope

**In scope:**

- The crate's OIDC authorization-code flow (login, callback, logout).
- Session handling and the session cookie hardening.
- Server-side token storage and the `Auth` extractor / `/auth/me` exposure
  boundary.
- Open-redirect (`return_to`) and logout CSRF defenses.

**Out of scope:**

- Vulnerabilities in the identity provider (IdP) itself.
- Vulnerabilities in consumer applications that mount these routes, including
  their `SessionRepository` implementations and deployment configuration.
- Use of `CookieSessionStore` in production (documented as unsupported; see the
  README).

## Known advisories

- **RUSTSEC-2023-0071** (Marvin attack timing side-channel in the `rsa` crate)
  is ignored in `deny.toml` (`[advisories] ignore`). This crate only performs
  RSA **public-key** operations — verifying JWT/ID-token signatures — and never
  RSA private-key operations, so the timing side-channel is not reachable here.
  This ignore must be **re-evaluated** if RSA private-key operations are ever
  introduced (for example, `private_key_jwt` client authentication or
  JWE-encrypted ID tokens), and dropped once `rsa` 0.10 ships.
