package d1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const apiBase = "https://api.cloudflare.com/client/v4"

type Config struct {
	AccountID  string
	DatabaseID string
	APIToken   string
}

type Client struct {
	cfg  Config
	http *http.Client
}

func New(cfg Config) *Client {
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 60 * time.Second},
	}
}

type queryRequest struct {
	SQL    string `json:"sql"`
	Params []any  `json:"params,omitempty"`
}

type apiResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result []struct {
		Results []map[string]any `json:"results"`
		Success bool             `json:"success"`
		Error   string           `json:"error"`
	} `json:"result"`
}

func (c *Client) Exec(ctx context.Context, sql string, params ...any) error {
	_, err := c.query(ctx, sql, params...)
	return err
}

func (c *Client) QueryRowScan(ctx context.Context, sql string, cols []string, params []any, dest ...any) error {
	rows, err := c.query(ctx, sql, params...)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return ErrNoRows
	}
	if len(cols) != len(dest) {
		return fmt.Errorf("d1: column count mismatch")
	}
	row := rows[0]
	for i, col := range cols {
		if err := assign(row[col], dest[i]); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) query(ctx context.Context, sql string, params ...any) ([]map[string]any, error) {
	url := fmt.Sprintf("%s/accounts/%s/d1/database/%s/query", apiBase, c.cfg.AccountID, c.cfg.DatabaseID)

	body, err := json.Marshal(queryRequest{SQL: sql, Params: params})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("d1 request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var out apiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode d1 response: %w", err)
	}
	if !out.Success {
		if len(out.Errors) > 0 {
			return nil, fmt.Errorf("d1 error: %s", out.Errors[0].Message)
		}
		return nil, fmt.Errorf("d1 error: %s", string(raw))
	}
	if len(out.Result) == 0 {
		return nil, nil
	}
	if out.Result[0].Error != "" {
		return nil, fmt.Errorf("d1 query error: %s", out.Result[0].Error)
	}
	return out.Result[0].Results, nil
}

var ErrNoRows = fmt.Errorf("d1: no rows")

func assign(src any, dest any) error {
	if src == nil {
		return nil
	}
	switch d := dest.(type) {
	case *string:
		*d = fmt.Sprint(src)
	case *int:
		switch v := src.(type) {
		case float64:
			*d = int(v)
		case int:
			*d = v
		case int64:
			*d = int(v)
		default:
			fmt.Sscanf(fmt.Sprint(src), "%d", d)
		}
	case *float64:
		switch v := src.(type) {
		case float64:
			*d = v
		case int:
			*d = float64(v)
		case int64:
			*d = float64(v)
		case string:
			fmt.Sscanf(v, "%f", d)
		default:
			fmt.Sscanf(fmt.Sprint(src), "%f", d)
		}
	default:
		return fmt.Errorf("unsupported scan type %T", dest)
	}
	return nil
}

func (c *Client) Migrate(ctx context.Context, schema string) error {
	for _, stmt := range splitStatements(schema) {
		if err := c.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w\nstmt: %s", err, stmt)
		}
	}
	return nil
}

func splitStatements(schema string) []string {
	var out []string
	for _, part := range strings.Split(schema, ";") {
		s := strings.TrimSpace(part)
		if s == "" || strings.HasPrefix(strings.ToUpper(s), "PRAGMA") {
			continue
		}
		out = append(out, s)
	}
	return out
}
