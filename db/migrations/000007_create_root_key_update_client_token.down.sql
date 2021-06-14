BEGIN;
ALTER TABLE client_tokens DROP CONSTRAINT IF EXISTS client_tokens_uuid_root_keys_uuid_foreign;
ALTER TABLE client_tokens DROP COLUMN IF EXISTS expires_at;
DROP TABLE root_keys;
COMMIT;