-- Drop SGA/Admin field on systems
-- Drop useful constraints

BEGIN;

ALTER TABLE public.systems DROP COLUMN sga_key;

ALTER TABLE public.systems DROP CONSTRAINT IF EXISTS systems_client_id_key;
ALTER TABLE public.groups DROP CONSTRAINT IF EXISTS groups_group_id_key;

COMMIT;
