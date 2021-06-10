BEGIN;
CREATE SEQUENCE public.client_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE public.client_tokens (
    id integer DEFAULT nextval('public.client_tokens_id_seq'::regclass) NOT NULL ,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    label text,
    uuid text not null,
    system_id integer,
    UNIQUE(uuid)
);
ALTER SEQUENCE public.client_tokens_id_seq OWNED BY public.client_tokens.id;
COMMIT;