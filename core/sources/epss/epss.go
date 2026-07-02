package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/abdulmalik/k8sradar/core/cache"
)

const apiBase = "https://api.first.org/data/v1/epss"

type Client struct {
	HTTP *http.Client
}

func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 120 * time.Second}}
}

type apiResponse struct {
	Status string `json:"status"`
	Total  int    `json:"total"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
	Data   []row  `json:"data"`
}

type row struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
}

func (c *Client) Sync(ctx context.Context, db *cache.DB) (int, error) {
	const pageSize = 1000
	offset := 0
	total := 0

	for {
		rows, more, err := c.fetchPage(ctx, offset, pageSize)
		if err != nil {
			return total, err
		}
		for _, r := range rows {
			score, err := strconv.ParseFloat(r.EPSS, 64)
			if err != nil {
				continue
			}
			pct, err := strconv.ParseFloat(r.Percentile, 64)
			if err != nil {
				continue
			}
			if err := db.UpsertEPSS(ctx, r.CVE, score, pct); err != nil {
				return total, err
			}
			total++
		}
		if !more {
			break
		}
		offset += pageSize
	}
	if err := db.SetSyncState(ctx, "epss", ""); err != nil {
		return total, err
	}
	return total, nil
}

func (c *Client) fetchPage(ctx context.Context, offset, limit int) ([]row, bool, error) {
	u, _ := url.Parse(apiBase)
	q := u.Query()
	q.Set("offset", strconv.Itoa(offset))
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("fetch epss: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("epss status: %s", resp.Status)
	}

	var payload apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode epss: %w", err)
	}

	more := offset+len(payload.Data) < payload.Total
	return payload.Data, more, nil
}

func (c *Client) Lookup(ctx context.Context, db *cache.DB, cveIDs []string) error {
	if len(cveIDs) == 0 {
		return nil
	}

	var pending []string
	for _, id := range cveIDs {
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		if score, _, ok, _ := db.GetEPSS(ctx, id); ok && score > 0 {
			continue
		}
		pending = append(pending, id)
	}

	const batchSize = 50
	for i := 0; i < len(pending); i += batchSize {
		end := i + batchSize
		if end > len(pending) {
			end = len(pending)
		}
		if err := c.lookupBatch(ctx, db, pending[i:end]); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) lookupBatch(ctx context.Context, db *cache.DB, cveIDs []string) error {
	u, _ := url.Parse(apiBase)
	q := u.Query()
	q.Set("cve", strings.Join(cveIDs, ","))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("epss lookup status: %s", resp.Status)
	}

	var payload apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	for _, r := range payload.Data {
		score, _ := strconv.ParseFloat(r.EPSS, 64)
		pct, _ := strconv.ParseFloat(r.Percentile, 64)
		if err := db.UpsertEPSS(ctx, r.CVE, score, pct); err != nil {
			return err
		}
	}
	return nil
}
