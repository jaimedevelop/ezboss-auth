BEGIN;
SET LOCAL search_path=ezboss_auth;
ALTER TABLE "user" ADD COLUMN "acceptedTermsVersion" text;
ALTER TABLE "user" ADD COLUMN "acceptedPrivacyVersion" text;
ALTER TABLE "user" ADD COLUMN "termsAcceptedAt" timestamptz;
COMMIT;
