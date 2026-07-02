package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/abdulmalik/k8sradar/core/cache"
)

const feedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type Client struct {
	HTTP *http.Client
}

func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 60 * time.Second}}
}

type feed struct {
	Vulnerabilities []entry `json:"vulnerabilities"`
}

type entry struct {
	CVEID          string `json:"cveID"`
	DateAdded      string `json:"dateAdded"`
	RequiredAction string `json:"requiredAction"`
}

func (c *Client) Sync(ctx context.Context, db *cache.DB) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return 0, err
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch kev: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("kev status: %s", resp.Status)
	}

	var f feed
	if err := json.NewDecoder(resp.Body).Decode(&f); err != nil {
		return 0, fmt.Errorf("decode kev: %w", err)
	}

	for _, e := range f.Vulnerabilities {
		if err := db.UpsertKEV(ctx, e.CVEID, e.DateAdded, e.RequiredAction); err != nil {
			return 0, err
		}
	}

	if err := db.SetSyncState(ctx, "kev", ""); err != nil {
		return 0, err
	}
	return len(f.Vulnerabilities), nil
}
