BEGIN;
ALTER TABLE client_tokens DROP COLUMN IF EXISTS expires_at;
DROP TABLE root_keys;
COMMIT;