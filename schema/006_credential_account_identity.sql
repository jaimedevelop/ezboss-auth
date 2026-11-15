-- First-password setup must have exactly one credential slot per EzBoss identity.
CREATE UNIQUE INDEX "account_credential_user_uidx"
  ON ezboss_auth."account" ("userId") WHERE "providerId" = 'credential';
