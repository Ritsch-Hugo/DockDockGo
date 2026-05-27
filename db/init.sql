-- Schéma DocDockGo — exécuté automatiquement par le conteneur postgres au premier démarrage

CREATE FUNCTION public.notify_dashboard_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('dashboard_changes', TG_TABLE_NAME);
  RETURN NULL;
END;
$$;

CREATE TABLE public.pulls (
    uuid uuid NOT NULL,
    ip_client character varying(45) NOT NULL,
    registry character varying(255) NOT NULL,
    repository character varying(255) NOT NULL,
    tag character varying(100),
    os character varying(50),
    arch character varying(50),
    client_type character varying(50),
    started_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_activity timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    scan_completed boolean DEFAULT false,
    decision_final character varying(50),
    CONSTRAINT pulls_pkey PRIMARY KEY (uuid)
);

CREATE TABLE public.pull_digests (
    id uuid NOT NULL,
    pull_id uuid NOT NULL,
    digest_value character varying(255) NOT NULL,
    digest_type character varying(50),
    received_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    digest_algo character varying(20),
    CONSTRAINT pull_digests_pkey PRIMARY KEY (id),
    CONSTRAINT fk_pull_digest FOREIGN KEY (pull_id) REFERENCES public.pulls(uuid) ON DELETE CASCADE
);

CREATE UNIQUE INDEX uq_pull_digests ON public.pull_digests (pull_id, digest_value, digest_type);

CREATE TABLE public.ia_decisions (
    id uuid NOT NULL,
    pull_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    decision character varying(20),
    dynamic_scan boolean DEFAULT false,
    compliance_scan boolean DEFAULT false,
    static_scan boolean DEFAULT false,
    vulnerability_score double precision DEFAULT 0.0,
    confidence double precision DEFAULT 0.0,
    rationale text,
    scan_reasoning jsonb,
    decision_metadata jsonb,
    alternatives jsonb,
    CONSTRAINT ia_decisions_pkey PRIMARY KEY (id),
    CONSTRAINT fk_pull_ia FOREIGN KEY (pull_id) REFERENCES public.pulls(uuid) ON DELETE CASCADE
);

CREATE TABLE public.scan_events (
    id uuid NOT NULL,
    pull_id uuid NOT NULL,
    ia_decision_id uuid,
    scanner_type character varying(100),
    response_scanner jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    executed boolean DEFAULT false NOT NULL,
    llm_summary text,
    CONSTRAINT scan_events_pkey PRIMARY KEY (id),
    CONSTRAINT fk_pull_scan FOREIGN KEY (pull_id) REFERENCES public.pulls(uuid) ON DELETE CASCADE,
    CONSTRAINT fk_ia_decision FOREIGN KEY (ia_decision_id) REFERENCES public.ia_decisions(id) ON DELETE SET NULL
);

CREATE TABLE public.whitelist (
    id uuid NOT NULL,
    registry character varying(255) NOT NULL,
    repository character varying(255) NOT NULL,
    tag character varying(100),
    added_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT whitelist1_pkey PRIMARY KEY (id),
    CONSTRAINT whitelist_registry_repo_tag_unique UNIQUE (registry, repository, tag)
);

CREATE TABLE public.blacklist (
    id uuid NOT NULL,
    registry character varying(255) NOT NULL,
    repository character varying(255) NOT NULL,
    tag character varying(100),
    added_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT blacklist_pkey PRIMARY KEY (id),
    CONSTRAINT blacklist_registry_repo_tag_unique UNIQUE (registry, repository, tag)
);

CREATE TABLE public.cache (
    id uuid NOT NULL,
    registry character varying(255) NOT NULL,
    repository character varying(255) NOT NULL,
    digest character varying(255) NOT NULL,
    type character varying(50),
    file_path character varying(512),
    size_bytes bigint,
    added_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    digest_algo character varying(20),
    CONSTRAINT cache_pkey PRIMARY KEY (id)
);

CREATE UNIQUE INDEX uq_cache ON public.cache (registry, repository, digest, type);

CREATE TABLE public.quarantine (
    id uuid NOT NULL,
    registry character varying(255) NOT NULL,
    repository character varying(255) NOT NULL,
    digest character varying(255) NOT NULL,
    type character varying(50),
    file_path character varying(512),
    size_bytes bigint,
    added_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    digest_algo character varying(20),
    CONSTRAINT quarantine_pkey PRIMARY KEY (id)
);

CREATE UNIQUE INDEX uq_quarantine ON public.quarantine (registry, repository, digest, type);

CREATE TABLE public.users (
    username character varying(100),
    role character varying(20) NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    allowed_ips text[] DEFAULT '{}'::text[],
    sub character varying(100) NOT NULL,
    last_login timestamp with time zone,
    CONSTRAINT users_pkey PRIMARY KEY (sub)
);

CREATE UNIQUE INDEX users_username_key ON public.users (username);

-- Triggers de notification dashboard (LISTEN/NOTIFY)
CREATE TRIGGER trg_notify_all AFTER INSERT OR DELETE OR UPDATE ON public.pulls         FOR EACH ROW EXECUTE FUNCTION public.notify_dashboard_change();
CREATE TRIGGER trg_notify_all AFTER INSERT OR DELETE OR UPDATE ON public.pull_digests  FOR EACH ROW EXECUTE FUNCTION public.notify_dashboard_change();
CREATE TRIGGER trg_notify_all AFTER INSERT OR DELETE OR UPDATE ON public.ia_decisions  FOR EACH ROW EXECUTE FUNCTION public.notify_dashboard_change();
CREATE TRIGGER trg_notify_all AFTER INSERT OR DELETE OR UPDATE ON public.scan_events   FOR EACH ROW EXECUTE FUNCTION public.notify_dashboard_change();
CREATE TRIGGER trg_notify_all AFTER INSERT OR DELETE OR UPDATE ON public.whitelist     FOR EACH ROW EXECUTE FUNCTION public.notify_dashboard_change();
CREATE TRIGGER trg_notify_all AFTER INSERT OR DELETE OR UPDATE ON public.blacklist     FOR EACH ROW EXECUTE FUNCTION public.notify_dashboard_change();
CREATE TRIGGER trg_notify_all AFTER INSERT OR DELETE OR UPDATE ON public.cache         FOR EACH ROW EXECUTE FUNCTION public.notify_dashboard_change();
CREATE TRIGGER trg_notify_all AFTER INSERT OR DELETE OR UPDATE ON public.quarantine    FOR EACH ROW EXECUTE FUNCTION public.notify_dashboard_change();
CREATE TRIGGER trg_notify_all AFTER INSERT OR DELETE OR UPDATE ON public.users         FOR EACH ROW EXECUTE FUNCTION public.notify_dashboard_change();
