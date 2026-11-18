CREATE TABLE catalog_candidates (
    id            text PRIMARY KEY,
    source        text NOT NULL,
    title         text NOT NULL,
    description   text NOT NULL,
    status        text NOT NULL,
    techniques    text[] NOT NULL,
    platforms     text[] NOT NULL,          -- platforms with a first-draft query
    score         integer NOT NULL,
    tier          text NOT NULL,
    fingerprint   text NOT NULL,
    body          jsonb NOT NULL,           -- the whole Candidate
    search        tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector('english', title), 'A') ||
        setweight(to_tsvector('english', description), 'B')
    ) STORED
);

CREATE INDEX catalog_candidates_search ON catalog_candidates USING gin (search);
CREATE INDEX catalog_candidates_techniques ON catalog_candidates USING gin (techniques);
CREATE INDEX catalog_candidates_fingerprint ON catalog_candidates (fingerprint);
