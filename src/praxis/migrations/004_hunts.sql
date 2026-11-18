CREATE TABLE hunts (
    id          text PRIMARY KEY,
    prompt      text        NOT NULL,
    clients     text[]      NOT NULL,
    pr_url      text,
    body        jsonb       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
