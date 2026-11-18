CREATE TABLE coverage_snapshots (
    id             bigserial PRIMARY KEY,
    client_id      text        NOT NULL,
    taken_at       timestamptz NOT NULL,
    attack_version text        NOT NULL,
    summary        jsonb       NOT NULL,
    body           jsonb       NOT NULL,
    inventory      jsonb       NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX coverage_snapshots_client_time ON coverage_snapshots (client_id, taken_at DESC, id DESC);
