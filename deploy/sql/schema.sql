-- sluice decision store (PostgreSQL). Ingest JSONL traces with sluice.trace.sqlstore, then
-- query decisions/violations for a SOC dashboard alongside the OCSF/SIEM export.

CREATE TABLE IF NOT EXISTS sluice_session (
    session_id  TEXT PRIMARY KEY,
    mode        TEXT NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    policy      JSONB NOT NULL,
    tools       JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS sluice_decision (
    id           BIGSERIAL PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES sluice_session(session_id) ON DELETE CASCADE,
    call_id      TEXT NOT NULL,
    ts           DOUBLE PRECISION NOT NULL,
    tool         TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    args         JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (session_id, call_id)
);

CREATE TABLE IF NOT EXISTS sluice_violation (
    id           BIGSERIAL PRIMARY KEY,
    decision_id  BIGINT NOT NULL REFERENCES sluice_decision(id) ON DELETE CASCADE,
    arg          TEXT NOT NULL,
    label        TEXT NOT NULL,
    rule         TEXT NOT NULL,
    sources      JSONB NOT NULL DEFAULT '[]'::jsonb,
    failures     JSONB NOT NULL DEFAULT '[]'::jsonb,
    tags         JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS sluice_decision_verdict_idx ON sluice_decision (verdict);
CREATE INDEX IF NOT EXISTS sluice_decision_tool_idx ON sluice_decision (tool);
CREATE INDEX IF NOT EXISTS sluice_violation_arg_idx ON sluice_violation (arg);

-- Blocked/asked calls, newest first: the SOC's primary view.
CREATE OR REPLACE VIEW sluice_blocked AS
SELECT d.session_id, d.call_id, to_timestamp(d.ts) AS at, d.tool, d.verdict, d.reason,
       v.arg, v.label, v.rule, v.sources, v.tags
FROM sluice_decision d
JOIN sluice_violation v ON v.decision_id = d.id
WHERE d.verdict IN ('block', 'ask')
ORDER BY d.ts DESC;
