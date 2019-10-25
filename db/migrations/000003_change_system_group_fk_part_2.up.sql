BEGIN;
DROP TRIGGER before_trigger_on_systems ON public.systems;

DROP FUNCTION func_before_trigger_on_systems();
COMMIT;