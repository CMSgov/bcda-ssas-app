-- Revert rename table to denylist_entries

BEGIN;

ALTER TABLE denylist_entries 
RENAME TO blacklist_entries;

ALTER SEQUENCE denylist_entries_id_seq
RENAME TO blacklist_entries_id_seq ;

COMMIT;
