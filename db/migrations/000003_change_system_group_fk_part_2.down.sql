BEGIN;
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
