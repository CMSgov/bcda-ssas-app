BEGIN;

CREATE SEQUENCE public.root_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE public.root_keys (
  id integer DEFAULT nextval('public.root_keys_id_seq'::regclass) NOT NULL ,
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  deleted_at timestamp with time zone,
  expires_at timestamp with time zone,
  uuid text not null,
  key text not null,
  UNIQUE(uuid)
);
ALTER SEQUENCE public.root_keys_id_seq OWNED BY public.root_keys.id;

ALTER TABLE public.client_tokens
ADD COLUMN expires_at timestamp with time zone;

ALTER TABLE public.client_tokens
ADD CONSTRAINT client_tokens_uuid_root_keys_uuid_foreign FOREIGN KEY (uuid) REFERENCES public.root_keys(uuid) ON UPDATE RESTRICT ON DELETE RESTRICT;

END;
COMMIT;
