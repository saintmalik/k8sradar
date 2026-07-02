package cache

import (
	"context"
	"database/sql"
	"time"
)

func (db *DB) Exec(ctx context.Context, q string, args ...any) error {
	return db.exec(ctx, q, args...)
}

func (db *DB) SetMeta(ctx context.Context, key, value string) error {
	return db.Exec(ctx, `
		INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
}

func (db *DB) GetMeta(ctx context.Context, key string) (string, error) {
	var value string
	err := db.row(ctx, `SELECT value FROM meta WHERE key = ?`, []string{"value"}, []any{key}, &value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}
