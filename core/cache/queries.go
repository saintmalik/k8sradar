package cache

import (
	"context"
	"database/sql"
)

type CVE struct {
	ID          string
	Description string
	CVSSScore   float64
	CVSSVector  string
	Published   string
}

func (db *DB) UpsertCVE(ctx context.Context, c CVE, rawJSON string) error {
	return db.exec(ctx, `
		INSERT INTO cves (id, description, cvss_score, cvss_vector, published, raw_json)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			description = excluded.description,
			cvss_score = excluded.cvss_score,
			cvss_vector = excluded.cvss_vector,
			published = excluded.published,
			raw_json = excluded.raw_json
	`, c.ID, c.Description, c.CVSSScore, c.CVSSVector, c.Published, rawJSON)
}

func (db *DB) GetCVE(ctx context.Context, id string) (*CVE, error) {
	var c CVE
	err := db.row(ctx, `
		SELECT id, description, cvss_score, cvss_vector, published FROM cves WHERE id = ?
	`, []string{"id", "description", "cvss_score", "cvss_vector", "published"}, []any{id},
		&c.ID, &c.Description, &c.CVSSScore, &c.CVSSVector, &c.Published)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (db *DB) UpsertEPSS(ctx context.Context, cveID string, score, percentile float64) error {
	return db.exec(ctx, `
		INSERT INTO epss_scores (cve_id, score, percentile, fetched_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			score = excluded.score,
			percentile = excluded.percentile,
			fetched_at = excluded.fetched_at
	`, cveID, score, percentile, nowISO())
}

func (db *DB) GetEPSS(ctx context.Context, cveID string) (score, percentile float64, ok bool, err error) {
	err = db.row(ctx, `
		SELECT score, percentile FROM epss_scores WHERE cve_id = ?
	`, []string{"score", "percentile"}, []any{cveID}, &score, &percentile)
	if err == sql.ErrNoRows {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	return score, percentile, true, nil
}

func (db *DB) UpsertKEV(ctx context.Context, cveID, dateAdded, action string) error {
	return db.exec(ctx, `
		INSERT INTO kev_entries (cve_id, date_added, required_action)
		VALUES (?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			date_added = excluded.date_added,
			required_action = excluded.required_action
	`, cveID, dateAdded, action)
}

func (db *DB) InKEV(ctx context.Context, cveID string) (bool, error) {
	var n int
	err := db.row(ctx, `SELECT COUNT(1) AS n FROM kev_entries WHERE cve_id = ?`,
		[]string{"n"}, []any{cveID}, &n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return n > 0, err
}

func (db *DB) GetOSVCache(ctx context.Context, ecosystem, pkg, version string) (string, bool, error) {
	var raw string
	err := db.row(ctx, `
		SELECT raw_json FROM osv_cache WHERE ecosystem = ? AND package = ? AND version = ?
	`, []string{"raw_json"}, []any{ecosystem, pkg, version}, &raw)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return raw, true, nil
}

func (db *DB) SetOSVCache(ctx context.Context, ecosystem, pkg, version, rawJSON string) error {
	return db.exec(ctx, `
		INSERT INTO osv_cache (ecosystem, package, version, raw_json, fetched_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(ecosystem, package, version) DO UPDATE SET
			raw_json = excluded.raw_json,
			fetched_at = excluded.fetched_at
	`, ecosystem, pkg, version, rawJSON, nowISO())
}

func (db *DB) SetSyncState(ctx context.Context, source, cursor string) error {
	return db.exec(ctx, `
		INSERT INTO sync_state (source, last_sync, cursor)
		VALUES (?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET
			last_sync = excluded.last_sync,
			cursor = excluded.cursor
	`, source, nowISO(), cursor)
}

func (db *DB) CountKEV(ctx context.Context) (int, error) {
	var n int
	err := db.row(ctx, `SELECT COUNT(1) AS n FROM kev_entries`, []string{"n"}, nil, &n)
	return n, err
}

func (db *DB) CountEPSS(ctx context.Context) (int, error) {
	var n int
	err := db.row(ctx, `SELECT COUNT(1) AS n FROM epss_scores`, []string{"n"}, nil, &n)
	return n, err
}

func (db *DB) GetSyncState(ctx context.Context, source string) (lastSync string, err error) {
	err = db.row(ctx, `SELECT last_sync FROM sync_state WHERE source = ?`,
		[]string{"last_sync"}, []any{source}, &lastSync)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return lastSync, err
}

type CacheStats struct {
	KEVCount  int
	EPSSCount int
	CVECount  int
	KEVSync   string
	Backend   string
}

func (db *DB) Stats(ctx context.Context) (CacheStats, error) {
	var s CacheStats
	s.Backend = db.backend
	var err error
	s.KEVCount, err = db.CountKEV(ctx)
	if err != nil {
		return s, err
	}
	s.EPSSCount, err = db.CountEPSS(ctx)
	if err != nil {
		return s, err
	}
	err = db.row(ctx, `SELECT COUNT(1) AS n FROM cves`, []string{"n"}, nil, &s.CVECount)
	if err != nil {
		return s, err
	}
	s.KEVSync, _ = db.GetSyncState(ctx, "kev")
	return s, nil
}
