# EzBoss auth compatibility service

Pinned ESM Better Auth 1.7.17 proof service. **Not a cutover-ready replacement.** Existing clients and business routes still use Auth0. Do not route live users here yet. See [implementation ledger](../docs/architecture/BETTER_AUTH_IMPLEMENTATION.md).

Node 24.8.0, PostgreSQL 16+; `npm ci`, `npm run build`. Copy `.env.example` to an ignored local `.env` and supply independent secrets privately. The auth schema is isolated with `search_path=ezboss_auth`; the database role must not own or write business tables. Do not reuse application database ownership privileges.

Review/apply `schema/001_better_auth.sql`, `002_admin_assurance.sql`, `003_totp_replay.sql`, `004_identity_consent.sql` `005_google_account_identity.sql` and `006_credential_account_identity.sql` through a controlled target-checked migration job; startup never migrates. `npm run db:generate -- /tmp/review-auth-schema.sql` only compiles review SQL from an EMPTY disposable development schema; it never rewrites numbered migrations. The application-owned second migration is reviewed separately.

For real protocol tests, create a disposable loopback PostgreSQL database named `ezboss_auth_test` and run:

```sh
AUTH_TEST_DATABASE_URL=postgresql://local_role@127.0.0.1:5432/ezboss_auth_test npm test
```

Tests refuse other hosts/database names. They recreate **only** `ezboss_auth` in that disposable database; the business schema rehearsal rolls back its separate fixture schema. Missing PostgreSQL configuration is a failing gate, never a skipped success. Fixtures send no real email and use cryptographically signed synthetic WebAuthn assertions; they do not prove physical-device acceptance.

The service mounts `/api/auth/*` before body parsing, authenticated `/internal/verify-session` after bounded parsing, and health endpoints. Internal verification forwards one credential only, returns no credential material, does not renew sessions, and fails unavailable on database errors. Signed native bearers are required; the raw token in provider response JSON must not be persisted as a session bearer. MFA intermediate cookies belong only in a transient, isolated native cookie jar; persist the signed `set-auth-token` header only after a complete authenticated response and session verification. Browser clients use HTTP-only cookies and must never persist that header.

The bearer plugin MUST remain after the MFA plugin: a tested earlier order emitted a misleading token header on incomplete MFA. The application TOTP guard now consumes valid time steps atomically in shared PostgreSQL before any MFA session is issued. Enrollment, sign-in, concurrent replicas and older accepted steps share the factor high-water mark. Invalid codes retain provider lockout bookkeeping; storage/decryption failures deny access. A consumed step stays consumed after interruption, so retry with a new code. Tests assert enrollment-code replay rejection and exactly one winner among 24 concurrent claims. Other protocol/device gates remain pending.

`AdminStepUp` is an application-owned, tested primitive with atomic challenge consumption, strict WebAuthn user verification, RP/origin checks, account/session binding and five-minute assurance. Browser ceremony routes are exposed under `/api/auth/ezboss/admin/` with authenticated sessions, CSRF/origin checks and a shared wrapper limiter. The web dialog uses these routes and verifies account/session continuity before a single safe retry. Ordinary passkey/TOTP login confers no administrator assurance. Native privileged actions remain unavailable until their session-bound ceremony is accepted.

Auth email uses Mailgun over HTTPS. Configure `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, and `MAILGUN_FROM` on the auth service. Set `MAILGUN_REGION` to match the sending domain (`us` by default, or `eu` or `au`). Use a verified sending domain and a key with permission to send from it.

Google credentials/identity reconciliation, controlled mail retries, provider notices and lifecycle outbox consumers remain pending. Apple is a later addition. Google can be linked explicitly from an authenticated Better Auth account using a verified matching email. Automatic linking by email is disabled. OAuth dynamic registration is disabled; test clients are fixed database fixtures. Native OAuth client provisioning/resource-token introspection, full refresh lifecycle/revocation proof and browser return adapters remain pending; OAuth credentials are not accepted as session bearers.

Proxy policy currently discards caller-supplied forwarding headers and uses the immediate peer for shared database rate limits. Before Railway rollout, prove an ingress that overwrites trusted forwarding headers, direct-origin containment, account/IP limits, body/concurrency limits and same-origin `/api/auth` routing. Without that proof all proxied clients may share the peer's limit. Do not disable rate limits or CSRF to work around topology failures.

Container and Railway manifest are prepared but un-deployed. Never expose `/internal/*` publicly as an intended ingress route; service-key authentication is still mandatory on private networking. Add network enforcement, full dependency/version readiness policy and load/outage/restore evidence before launch. Readiness checks the required session/replay/assurance/consent schema. No live accounts were imported or changed.

Legal publication uses optional server-only `AUTH_TERMS_VERSION`, `AUTH_PRIVACY_VERSION`, `AUTH_TERMS_URL`, and `AUTH_PRIVACY_URL` (all four or none; URLs must use the public app origin). Password signup is unavailable until approved documents are configured; accepted versions and a server timestamp are persisted. Google can be configured with both `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, kept only on the server. `/api/auth/ezboss/config` returns public provider/legal metadata, never secrets. First-time social identities must accept the current documents before business provisioning. Approved content and real provider callbacks are still pending.

Production gates still include account/IP abuse policy, strong administrator enrollment/removal/recovery policy, lifecycle workers, OAuth resource verification, native associations/security journeys, real providers/devices and the preserved nine-account rehearsal. The available UI and green local tests are not cutover acceptance.

## Google and password account linking

Apply migration 006 before rollout. It requires at most one credential row per user; inspect and resolve any existing duplicates before retrying a failed migration. Deploy the auth service and web bundle together: the public `/link-social` endpoint is disabled and the new web flow uses `/api/auth/ezboss/merge`. Existing Google provider, email delivery, and Authenticator configuration are reused.

Email-first users re-enter their EzBoss password, verify with their enrolled authenticator or a one-time email code, and select the verified Google account with the matching email. A failed password sign-in for an eligible Google-only account sends setup instructions to its verified mailbox. The user completes a Google redirect and verifies a code before adding a password. Email recovery continues to reset existing passwords only. The two methods share the existing EzBoss user ID; separate users and their business data are never consolidated. On iOS and Android, the setup email opens the hosted flow in the device browser. Users return to the app and sign in with their password. Users with an enrolled authenticator still sign in with their EzBoss password and authenticator code; the Google sign-in callback does not complete EzBoss MFA.
