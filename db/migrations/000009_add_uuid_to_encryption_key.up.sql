BEGIN;

ALTER TABLE ONLY public.encryption_keys
    ADD COLUMN uuid text;

COMMIT;