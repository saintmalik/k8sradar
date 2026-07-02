PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS cves (
    id TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    cvss_score REAL NOT NULL DEFAULT 0,
    cvss_vector TEXT NOT NULL DEFAULT '',
    published TEXT NOT NULL DEFAULT '',
    raw_json TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS cpe_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    cpe_name TEXT NOT NULL,
    version_start TEXT NOT NULL DEFAULT '',
    version_end TEXT NOT NULL DEFAULT '',
    vulnerable INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (cve_id) REFERENCES cves(id)
);

CREATE INDEX IF NOT EXISTS idx_cpe_matches_cve ON cpe_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_cpe_matches_name ON cpe_matches(cpe_name);

CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id TEXT PRIMARY KEY,
    score REAL NOT NULL DEFAULT 0,
    percentile REAL NOT NULL DEFAULT 0,
    fetched_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS kev_entries (
    cve_id TEXT PRIMARY KEY,
    date_added TEXT NOT NULL DEFAULT '',
    required_action TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS osv_cache (
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    raw_json TEXT NOT NULL DEFAULT '',
    fetched_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ecosystem, package, version)
);

CREATE TABLE IF NOT EXISTS sync_state (
    source TEXT PRIMARY KEY,
    last_sync TEXT NOT NULL DEFAULT '',
    cursor TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
