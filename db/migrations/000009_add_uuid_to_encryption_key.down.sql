BEGIN;

ALTER TABLE ONLY public.encryption_keys
    drop COLUMN if exists uuid;

COMMIT;