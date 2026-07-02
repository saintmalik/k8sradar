package cache

import (
	"context"
	"database/sql"

	"github.com/abdulmalik/k8sradar/core/d1"
)

type querier interface {
	Exec(ctx context.Context, sql string, params ...any) error
	QueryRowScan(ctx context.Context, sql string, cols []string, params []any, dest ...any) error
	Close() error
}

type sqliteDriver struct {
	db *sql.DB
}

func (d *sqliteDriver) Exec(ctx context.Context, sql string, params ...any) error {
	_, err := d.db.ExecContext(ctx, sql, params...)
	return err
}

func (d *sqliteDriver) QueryRowScan(ctx context.Context, query string, _ []string, params []any, dest ...any) error {
	row := d.db.QueryRowContext(ctx, query, params...)
	if err := row.Scan(dest...); err == sql.ErrNoRows {
		return d1.ErrNoRows
	} else if err != nil {
		return err
	}
	return nil
}

func (d *sqliteDriver) Close() error {
	return d.db.Close()
}

type d1Driver struct {
	client *d1.Client
}

func (d *d1Driver) Exec(ctx context.Context, sql string, params ...any) error {
	return d.client.Exec(ctx, sql, params...)
}

func (d *d1Driver) QueryRowScan(ctx context.Context, sql string, cols []string, params []any, dest ...any) error {
	return d.client.QueryRowScan(ctx, sql, cols, params, dest...)
}

func (d *d1Driver) Close() error {
	return nil
}
