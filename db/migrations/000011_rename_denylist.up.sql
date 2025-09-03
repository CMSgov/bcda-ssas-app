-- Rename table to denylist_entries

BEGIN;

ALTER TABLE blacklist_entries
RENAME TO denylist_entries;

ALTER SEQUENCE blacklist_entries_id_seq  
RENAME TO denylist_entries_id_seq;

COMMIT;
