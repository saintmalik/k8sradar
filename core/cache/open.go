package cache

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/abdulmalik/k8sradar/core/config"
	"github.com/abdulmalik/k8sradar/core/d1"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

type DB struct {
	q    querier
	backend string
}

func (db *DB) Backend() string { return db.backend }

func Open(cfg config.Config) (*DB, error) {
	if cfg.UseD1() {
		db, err := openD1(cfg)
		if err == nil {
			return db, nil
		}
		log.Printf("d1 unavailable, falling back to sqlite: %v", err)
	}
	return openSQLite(cfg.DBPath)
}

func openD1(cfg config.Config) (*DB, error) {
	client := d1.New(d1.Config{
		AccountID:  cfg.CFAccountID,
		DatabaseID: cfg.CFD1DatabaseID,
		APIToken:   cfg.D1Token(),
	})
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return nil, err
	}
	if err := client.Migrate(context.Background(), string(schema)); err != nil {
		return nil, fmt.Errorf("d1 migrate: %w", err)
	}
	return &DB{q: &d1Driver{client: client}, backend: "d1"}, nil
}

func openSQLite(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := copySeed(path); err != nil {
			if err := initEmpty(path); err != nil {
				return nil, err
			}
		}
	}

	sqlDB, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	db := &DB{q: &sqliteDriver{db: sqlDB}, backend: "sqlite"}
	if err := db.migrateSQLite(sqlDB); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) Close() error {
	if db.q == nil {
		return nil
	}
	return db.q.Close()
}

func (db *DB) migrateSQLite(sqlDB *sql.DB) error {
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	if _, err := sqlDB.Exec(string(schema)); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

func copySeed(dst string) error {
	candidates := []string{
		"internal/cache/seed/k8sradar.db",
		filepath.Join(filepath.Dir(os.Args[0]), "internal/cache/seed/k8sradar.db"),
		"/app/internal/cache/seed/k8sradar.db",
	}
	for _, src := range candidates {
		if err := copyFile(src, dst); err == nil {
			return nil
		}
	}
	return fmt.Errorf("seed not found")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func initEmpty(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()

	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	_, err = db.Exec(string(schema))
	return err
}

func (db *DB) exec(ctx context.Context, q string, args ...any) error {
	return db.q.Exec(ctx, q, args...)
}

func (db *DB) row(ctx context.Context, q string, cols []string, args []any, dest ...any) error {
	err := db.q.QueryRowScan(ctx, q, cols, args, dest...)
	if err == d1.ErrNoRows {
		return sql.ErrNoRows
	}
	return err
}
