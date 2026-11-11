-- Application-owned assurance; ordinary passkey sign-in never creates this record.
BEGIN;
SET LOCAL search_path=ezboss_auth;
CREATE TABLE admin_challenges (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 "userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
 "sessionId" text NOT NULL REFERENCES "session"(id) ON DELETE CASCADE,
 challenge text NOT NULL UNIQUE,
 "expiresAt" timestamptz NOT NULL DEFAULT now()+interval '2 minutes'
);
CREATE INDEX admin_challenges_expiry_idx ON admin_challenges("expiresAt");
CREATE TABLE admin_assurance (
 "sessionId" text PRIMARY KEY REFERENCES "session"(id) ON DELETE CASCADE,
 "userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
 "verifiedAt" timestamptz NOT NULL DEFAULT now(),
 method text NOT NULL CHECK (method='webauthn-uv')
);
COMMIT;
