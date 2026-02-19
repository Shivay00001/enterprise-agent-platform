-- ============================================================
-- Enterprise AI Agent Platform — Database Schema
-- Postgres 15+
-- All tables use UUID primary keys (time-ordered UUIDv7).
-- Sensitive fields are encrypted at the application layer.
-- ============================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- ORGANISATIONS
-- ============================================================
CREATE TABLE organisations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL UNIQUE,
    plan            TEXT NOT NULL DEFAULT 'starter', -- starter | pro | enterprise
    settings        JSONB NOT NULL DEFAULT '{}',
    -- Billing limits
    monthly_token_budget    BIGINT NOT NULL DEFAULT 1000000,
    monthly_cost_budget_usd DECIMAL(10,4) NOT NULL DEFAULT 100.00,
    -- Compliance settings
    robots_check_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    hitl_required_risk      DECIMAL(3,2) NOT NULL DEFAULT 0.60,
    -- Timestamps
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX idx_organisations_slug ON organisations(slug) WHERE deleted_at IS NULL;

-- ============================================================
-- USERS
-- ============================================================
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organisations(id),
    email           TEXT NOT NULL UNIQUE,
    -- Password stored as bcrypt hash; never plaintext.
    password_hash   TEXT,
    role            TEXT NOT NULL DEFAULT 'operator',
    -- CHECK constraint enforces valid roles at DB level.
    CONSTRAINT valid_role CHECK (role IN (
        'platform_admin', 'org_admin', 'operator',
        'hitl_reviewer', 'auditor', 'plugin_developer'
    )),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret_enc  TEXT, -- AES-256-GCM encrypted TOTP secret
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX idx_users_org_id ON users(org_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email ON users(lower(email)) WHERE deleted_at IS NULL;

-- ============================================================
-- TASKS
-- ============================================================
CREATE TABLE tasks (
    id              UUID PRIMARY KEY,
    correlation_id  UUID NOT NULL,
    org_id          UUID NOT NULL REFERENCES organisations(id),
    user_id         UUID NOT NULL REFERENCES users(id),
    -- Task definition
    description     TEXT NOT NULL, -- stored as-is (pre-sanitised at API layer)
    task_type       TEXT NOT NULL DEFAULT 'standard',
    status          TEXT NOT NULL DEFAULT 'pending',
    CONSTRAINT valid_status CHECK (status IN (
        'pending', 'planning', 'running', 'awaiting_human',
        'completed', 'failed', 'cancelled', 'budget_exceeded'
    )),
    -- Budget tracking
    token_budget    INTEGER NOT NULL,
    tokens_consumed INTEGER NOT NULL DEFAULT 0,
    cost_budget_usd DECIMAL(10,4) NOT NULL,
    cost_consumed_usd DECIMAL(10,6) NOT NULL DEFAULT 0,
    -- Results
    result_summary  TEXT,
    result_data     JSONB,
    error_message   TEXT,
    step_count      INTEGER NOT NULL DEFAULT 0,
    -- Metadata
    metadata        JSONB NOT NULL DEFAULT '{}',
    -- Risk tracking
    max_risk_score  DECIMAL(3,2),
    -- Temporal workflow reference
    temporal_workflow_id TEXT,
    temporal_run_id      TEXT,
    -- Timestamps
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    -- Partition key for time-based archiving
    partition_month TEXT GENERATED ALWAYS AS (to_char(created_at, 'YYYY-MM')) STORED
);

CREATE INDEX idx_tasks_org_id ON tasks(org_id, created_at DESC);
CREATE INDEX idx_tasks_user_id ON tasks(user_id, created_at DESC);
CREATE INDEX idx_tasks_status ON tasks(status) WHERE status IN ('pending', 'running', 'awaiting_human');
CREATE INDEX idx_tasks_correlation_id ON tasks(correlation_id);
CREATE INDEX idx_tasks_partition_month ON tasks(partition_month);

-- ============================================================
-- TASK STEPS (agent loop iterations)
-- ============================================================
CREATE TABLE task_steps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id         UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    step_number     INTEGER NOT NULL,
    -- LLM interaction
    thought         TEXT,
    tool_calls      JSONB, -- array of tool call objects
    observations    JSONB, -- array of tool results
    -- Metrics
    input_tokens    INTEGER,
    output_tokens   INTEGER,
    cost_usd        DECIMAL(10,6),
    model_used      TEXT,
    provider_used   TEXT,
    -- Timing
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    UNIQUE (task_id, step_number)
);

CREATE INDEX idx_task_steps_task_id ON task_steps(task_id);

-- ============================================================
-- HITL REVIEWS
-- ============================================================
CREATE TABLE hitl_reviews (
    id              UUID PRIMARY KEY,
    task_id         UUID NOT NULL REFERENCES tasks(id),
    org_id          UUID NOT NULL REFERENCES organisations(id),
    correlation_id  UUID NOT NULL,
    -- Request
    created_by      UUID NOT NULL REFERENCES users(id),
    question        TEXT NOT NULL,
    context_data    TEXT,
    proposed_action JSONB,
    risk_score      DECIMAL(3,2) NOT NULL,
    -- Decision
    status          TEXT NOT NULL DEFAULT 'pending',
    CONSTRAINT valid_review_status CHECK (status IN (
        'pending', 'approved', 'rejected', 'modified', 'expired', 'cancelled'
    )),
    reviewed_by     UUID REFERENCES users(id),
    review_note     TEXT,
    modified_args   JSONB,
    -- Timing
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    decided_at      TIMESTAMPTZ
);

CREATE INDEX idx_hitl_reviews_org_pending ON hitl_reviews(org_id, status) WHERE status = 'pending';
CREATE INDEX idx_hitl_reviews_task_id ON hitl_reviews(task_id);
CREATE INDEX idx_hitl_reviews_expires_at ON hitl_reviews(expires_at) WHERE status = 'pending';

-- ============================================================
-- TOOL REGISTRY
-- ============================================================
CREATE TABLE tools (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL,
    category        TEXT NOT NULL,
    CONSTRAINT valid_category CHECK (category IN (
        'read', 'write', 'compute', 'network', 'browser', 'destructive'
    )),
    parameters_schema JSONB NOT NULL,
    requires_hitl   BOOLEAN NOT NULL DEFAULT FALSE,
    max_runtime_ms  INTEGER NOT NULL DEFAULT 30000,
    -- Plugin management
    is_builtin      BOOLEAN NOT NULL DEFAULT TRUE,
    wasm_hash       TEXT, -- SHA-256 of WASM module for verification
    submitted_by    UUID REFERENCES users(id),
    approved_by     UUID REFERENCES users(id),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    -- Timestamps
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tools_name ON tools(name) WHERE is_active = TRUE;
CREATE INDEX idx_tools_category ON tools(category) WHERE is_active = TRUE;

-- ============================================================
-- AUDIT LOG (local queryable copy; primary is immutable S3+NATS)
-- ============================================================
CREATE TABLE audit_events (
    id              UUID PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    correlation_id  UUID,
    task_id         UUID,
    service         TEXT NOT NULL,
    -- Actor
    actor_type      TEXT NOT NULL,
    actor_id        TEXT NOT NULL,
    actor_ip        INET,
    -- Action
    action          TEXT NOT NULL,
    resource_type   TEXT,
    resource_id     TEXT,
    resource_org_id UUID,
    -- Outcome
    outcome         TEXT NOT NULL,
    risk_score      DECIMAL(3,2),
    error_message   TEXT,
    -- Metadata (searchable fields extracted from payload)
    metadata        JSONB,
    -- Cryptographic chain
    prev_hash       TEXT NOT NULL,
    event_hash      TEXT NOT NULL UNIQUE
) PARTITION BY RANGE (timestamp);

-- Create monthly partitions for the next 12 months.
-- In production, a cron job creates future partitions.
CREATE TABLE audit_events_2024_01 PARTITION OF audit_events
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
CREATE TABLE audit_events_2024_02 PARTITION OF audit_events
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
-- (additional partitions created by migration job)

CREATE INDEX idx_audit_events_task_id ON audit_events(task_id) WHERE task_id IS NOT NULL;
CREATE INDEX idx_audit_events_actor ON audit_events(actor_id, timestamp DESC);
CREATE INDEX idx_audit_events_action ON audit_events(action, timestamp DESC);
CREATE INDEX idx_audit_events_org ON audit_events(resource_org_id, timestamp DESC);
CREATE INDEX idx_audit_events_correlation ON audit_events(correlation_id) WHERE correlation_id IS NOT NULL;

-- ============================================================
-- RATE LIMIT TRACKING (persistent, complements Redis)
-- ============================================================
CREATE TABLE rate_limit_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier  TEXT NOT NULL, -- user_id or IP
    event_type  TEXT NOT NULL, -- task_create | api_call | domain_request
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (timestamp);

-- ============================================================
-- FUNCTIONS
-- ============================================================

-- Auto-update updated_at timestamp.
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_organisations_updated_at
    BEFORE UPDATE ON organisations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_tools_updated_at
    BEFORE UPDATE ON tools
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Budget enforcement function: check task budget before step insertion.
CREATE OR REPLACE FUNCTION check_task_budget()
RETURNS TRIGGER AS $$
DECLARE
    task_row tasks%ROWTYPE;
BEGIN
    SELECT * INTO task_row FROM tasks WHERE id = NEW.task_id;

    IF task_row.tokens_consumed + COALESCE(NEW.input_tokens, 0) + COALESCE(NEW.output_tokens, 0) > task_row.token_budget THEN
        RAISE EXCEPTION 'token_budget_exceeded'
            USING HINT = 'Task token budget exceeded',
                  ERRCODE = 'P0001';
    END IF;

    IF task_row.cost_consumed_usd + COALESCE(NEW.cost_usd, 0) > task_row.cost_budget_usd THEN
        RAISE EXCEPTION 'cost_budget_exceeded'
            USING HINT = 'Task cost budget exceeded',
                  ERRCODE = 'P0002';
    END IF;

    -- Update task totals.
    UPDATE tasks SET
        tokens_consumed = tokens_consumed + COALESCE(NEW.input_tokens, 0) + COALESCE(NEW.output_tokens, 0),
        cost_consumed_usd = cost_consumed_usd + COALESCE(NEW.cost_usd, 0),
        step_count = step_count + 1
    WHERE id = NEW.task_id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_task_budget
    BEFORE INSERT ON task_steps
    FOR EACH ROW EXECUTE FUNCTION check_task_budget();

-- ============================================================
-- ROW LEVEL SECURITY: Org data isolation
-- ============================================================
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE hitl_reviews ENABLE ROW LEVEL SECURITY;

-- Operators can only see their own org's data.
CREATE POLICY tasks_org_isolation ON tasks
    USING (org_id = current_setting('app.current_org_id', TRUE)::UUID);

CREATE POLICY hitl_reviews_org_isolation ON hitl_reviews
    USING (org_id = current_setting('app.current_org_id', TRUE)::UUID);

-- ============================================================
-- SEED DATA: Built-in tool definitions
-- ============================================================
INSERT INTO tools (name, description, category, parameters_schema, requires_hitl, is_builtin) VALUES
(
    'web_fetch',
    'Fetch text content from a public web page.',
    'network',
    '{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}',
    FALSE,
    TRUE
),
(
    'http_get',
    'Make an HTTP GET request to a public API.',
    'network',
    '{"type":"object","properties":{"url":{"type":"string"},"headers":{"type":"object"}},"required":["url"]}',
    FALSE,
    TRUE
),
(
    'json_parse',
    'Parse a JSON string into structured data.',
    'compute',
    '{"type":"object","properties":{"json_string":{"type":"string"}},"required":["json_string"]}',
    FALSE,
    TRUE
),
(
    'task_complete',
    'Signal task completion with a summary.',
    'compute',
    '{"type":"object","properties":{"summary":{"type":"string"},"result":{}},"required":["summary"]}',
    FALSE,
    TRUE
),
(
    'task_fail',
    'Signal that the task cannot be completed.',
    'compute',
    '{"type":"object","properties":{"reason":{"type":"string"}},"required":["reason"]}',
    FALSE,
    TRUE
),
(
    'request_human_input',
    'Escalate to a human operator for approval.',
    'compute',
    '{"type":"object","properties":{"question":{"type":"string"},"context":{"type":"string"}},"required":["question"]}',
    TRUE,
    TRUE
);
