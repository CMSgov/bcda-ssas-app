-- Revert rename table to denylist_entries

BEGIN;

ALTER TABLE public.denylist_entries 
RENAME TO public.blacklist_entries;

ALTER SEQUENCE public. denylist_entries_id_seq
RENAME TO public.blacklist_entries_id_seq ;

COMMIT;
