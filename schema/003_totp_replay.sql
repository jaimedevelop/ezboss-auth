-- Durable high-water mark shared by all replicas and all sessions for a factor.
-- Codes, decrypted secrets and hashes of low-entropy codes are never stored.
BEGIN;
SET LOCAL search_path=ezboss_auth;
CREATE TABLE totp_replay (
 "factorId" text PRIMARY KEY REFERENCES "twoFactor"(id) ON DELETE CASCADE,
 "lastStep" bigint NOT NULL CHECK ("lastStep">=0)
);
COMMIT;
