BEGIN;
CREATE TABLE IF NOT EXISTS public.blacklist_group_entries (
                                          id integer NOT NULL,
                                          created_at timestamp with time zone,
                                          updated_at timestamp with time zone,
                                          deleted_at timestamp with time zone,
                                          expression text NOT NULL,
                                          entry_date timestamp with time zone NOT NULL,
                                          cache_expiration timestamp with time zone NOT NULL,
                                          field text NOT NULL
);
CREATE SEQUENCE IF NOT EXISTS public.blacklist_group_entries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.blacklist_group_entries_id_seq OWNED BY public.blacklist_group_entries.id;
ALTER TABLE ONLY public.blacklist_group_entries ALTER COLUMN id SET DEFAULT nextval('public.blacklist_group_entries_id_seq'::regclass);
ALTER TABLE ONLY public.blacklist_group_entries
    ADD CONSTRAINT blacklist_group_entries_pkey PRIMARY KEY (id);
CREATE INDEX IF NOT EXISTS idx_blacklist_group_entries_deleted_at ON public.blacklist_group_entries USING btree (deleted_at);
COMMIT;