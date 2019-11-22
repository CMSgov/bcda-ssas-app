BEGIN;

CREATE TABLE public.ips (
    id integer NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    address INET NOT NULL,
    system_id integer NOT NULL
);
ALTER TABLE public.ips OWNER TO postgres;
CREATE SEQUENCE public.ips_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER TABLE public.ips_id_seq OWNER TO postgres;
ALTER SEQUENCE public.ips_id_seq OWNED BY public.ips.id;
ALTER TABLE ONLY public.ips ALTER COLUMN id SET DEFAULT nextval('public.ips_id_seq'::regclass);
ALTER TABLE ONLY public.ips
    ADD CONSTRAINT ips_pkey PRIMARY KEY (id);
CREATE INDEX idx_ips_deleted_at ON public.ips USING btree (deleted_at);
ALTER TABLE ONLY public.ips
    ADD CONSTRAINT ips_system_id_systems_id_foreign FOREIGN KEY (system_id) REFERENCES public.systems(id) ON UPDATE RESTRICT ON DELETE RESTRICT;

COMMIT;