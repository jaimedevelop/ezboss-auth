CREATE UNIQUE INDEX "account_google_subject_uidx"
  ON "account" ("accountId") WHERE "providerId" = 'google';
