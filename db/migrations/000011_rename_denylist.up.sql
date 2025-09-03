-- Rename table to denylist_entries

BEGIN;

ALTER TABLE public.blacklist_entries
RENAME TO public.denylist_entries;

ALTER SEQUENCE public.blacklist_entries_id_seq  
RENAME TO public.denylist_entries_id_seq;

COMMIT;
