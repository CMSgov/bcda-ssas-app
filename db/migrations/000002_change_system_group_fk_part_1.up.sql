BEGIN;
ALTER TABLE ONLY public.systems
    ADD COLUMN g_id int;

ALTER TABLE ONLY public.systems
    DROP CONSTRAINT systems_group_id_groups_group_id_foreign;

ALTER TABLE ONLY public.groups
    DROP CONSTRAINT groups_group_id_key;

UPDATE systems
SET g_id = groups.id
FROM groups
    WHERE systems.group_id = groups.group_id;

CREATE UNIQUE INDEX groups_group_id_deleted_at_key
    ON public.groups(group_id)
        WHERE deleted_at IS NULL;

ALTER TABLE ONLY public.systems
    ADD CONSTRAINT systems_g_id_groups_g_id_foreign FOREIGN KEY (g_id) REFERENCES public.groups(id) ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION func_before_trigger_on_systems()
    RETURNS trigger AS
$BODY$
BEGIN
    SELECT groups.id
    INTO NEW.g_id
    FROM groups
    WHERE groups.group_id = NEW.group_id;

    RETURN NEW;
END
$BODY$
    LANGUAGE plpgsql VOLATILE
                     COST 100;

CREATE TRIGGER before_trigger_on_systems
    BEFORE INSERT OR UPDATE
    ON public.systems
    FOR EACH ROW
EXECUTE PROCEDURE func_before_trigger_on_systems();
COMMIT;