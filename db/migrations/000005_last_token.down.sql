BEGIN;
ALTER TABLE ONLY public.systems
    DROP COLUMN last_token_at;

COMMIT;