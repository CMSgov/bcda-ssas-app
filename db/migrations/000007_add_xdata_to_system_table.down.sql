BEGIN;

ALTER TABLE ONLY public.systems
    drop COLUMN if exists x_data;

COMMIT;