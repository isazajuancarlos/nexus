-- Esquema inicial de NEXUS. Unifica el modelo mínimo de hacker/ (programs +
-- findings dedup por (url,vuln_name)) con el rico de bounty/ (estado de
-- verificación, retry adaptativo, logs de escaneo, scopes).
--
-- SQLite en WAL: mejor concurrencia lectura/escritura para el pool de workers.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS programs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    h1_handle         TEXT,
    platform          TEXT NOT NULL DEFAULT 'hackerone',
    status            TEXT NOT NULL DEFAULT 'pending',   -- pending|scanning|vulnerable|clean
    scope_status      TEXT NOT NULL DEFAULT 'pending',   -- pending|fetched|error|no_credentials
    last_scanned      TIMESTAMP,
    scope_fetched_at  TIMESTAMP,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Reglas de scope por programa (validación in-scope antes de escanear).
CREATE TABLE IF NOT EXISTS program_scopes (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id         INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    asset_identifier   TEXT NOT NULL,
    asset_type         TEXT NOT NULL,                    -- URL|WILDCARD|DOMAIN|CIDR|SOURCE_CODE
    eligible_for_bounty INTEGER NOT NULL DEFAULT 0,
    is_wildcard        INTEGER NOT NULL DEFAULT 0,
    base_domain        TEXT
);
CREATE INDEX IF NOT EXISTS ix_scope_program ON program_scopes(program_id);

CREATE TABLE IF NOT EXISTS findings (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id         INTEGER REFERENCES programs(id) ON DELETE SET NULL,
    program_name       TEXT,
    vuln_name          TEXT NOT NULL,                    -- template-id de nuclei
    vuln_type          TEXT,                             -- sqli|xss|rce|...
    severity           TEXT NOT NULL DEFAULT 'unknown',
    url                TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'NEW',      -- NEW|VERIFYING|VERIFIED|MANUAL_READY|REPORTED|FALSE_POSITIVE|ERROR|RETRY_PENDING
    verified           INTEGER NOT NULL DEFAULT 0,
    verification_tool  TEXT,
    verification_confidence TEXT,                        -- high|medium|low|none
    exploitable        INTEGER NOT NULL DEFAULT 0,
    verification_evidence TEXT,
    verified_at        TIMESTAMP,
    -- retry adaptativo
    retry_count        INTEGER NOT NULL DEFAULT 0,
    max_retries        INTEGER NOT NULL DEFAULT 3,
    next_retry_at      TIMESTAMP,
    last_error_type    TEXT,
    error_history      TEXT,                             -- JSON array
    found_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    notified           INTEGER NOT NULL DEFAULT 0
);
-- Dedup: la clave del sistema. (url, vuln_name) único (heredado de hacker/).
CREATE UNIQUE INDEX IF NOT EXISTS ix_finding_url_vuln ON findings(url, vuln_name);
CREATE INDEX IF NOT EXISTS ix_finding_status ON findings(status);

CREATE TABLE IF NOT EXISTS scan_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    program_name   TEXT,
    scan_type      TEXT NOT NULL,                        -- nuclei|subfinder|httpx|sqlmap|...
    phase          TEXT,
    started_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at   TIMESTAMP,
    status         TEXT NOT NULL DEFAULT 'running',      -- running|completed|failed|timeout
    findings_count INTEGER NOT NULL DEFAULT 0,
    error_message  TEXT
);
