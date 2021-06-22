BEGIN;

ALTER TABLE ONLY public.systems
    ADD COLUMN x_data text;

COMMIT;