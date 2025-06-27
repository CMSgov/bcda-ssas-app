-- Add SGA/Admin field on systems
-- Add useful constraints

BEGIN;

ALTER TABLE public.systems ADD COLUMN sga_key VARCHAR(64);

ALTER TABLE public.systems DROP CONSTRAINT IF EXISTS systems_client_id_key;
ALTER TABLE ONLY public.systems ADD CONSTRAINT systems_client_id_key UNIQUE (client_id);

ALTER TABLE public.groups DROP CONSTRAINT IF EXISTS groups_group_id_key;
ALTER TABLE ONLY public.groups ADD CONSTRAINT groups_group_id_key UNIQUE (group_id);

COMMIT;
