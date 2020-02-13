BEGIN;
ALTER TABLE ONLY public.systems
    ADD COLUMN last_token_at timestamp with time zone;

COMMIT;