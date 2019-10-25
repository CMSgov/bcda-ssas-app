BEGIN;
DROP TRIGGER before_trigger_on_systems
    ON systems;

DROP INDEX groups_group_id_deleted_at_key;

ALTER TABLE ONLY public.systems
    DROP CONSTRAINT systems_g_id_groups_g_id_foreign;

ALTER TABLE public.systems
    DROP COLUMN g_id;

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_group_id_key UNIQUE (group_id);

ALTER TABLE ONLY public.systems
    ADD CONSTRAINT systems_group_id_groups_group_id_foreign FOREIGN KEY (group_id) REFERENCES public.groups(group_id) ON UPDATE RESTRICT ON DELETE RESTRICT;
COMMIT;