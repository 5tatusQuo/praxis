CREATE TABLE pack_proposals (
    id          text PRIMARY KEY,           -- e.g. acme-2026.12.0
    client_id   text        NOT NULL,
    month       text        NOT NULL,
    status      text        NOT NULL,
    pr_url      text,
    body        jsonb       NOT NULL,       -- the rule-packs/<id>.yml record
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Every agent prompt, tool call, guardrail decision and pull request.
CREATE TABLE audit_log (
    id        bigserial PRIMARY KEY,
    at        timestamptz NOT NULL,
    actor     text        NOT NULL,         -- human:<name>, ai:<agent> or code:<part>
    client_id text,
    action    text        NOT NULL,
    detail    jsonb       NOT NULL
);

CREATE INDEX audit_log_client_time ON audit_log (client_id, at DESC);
