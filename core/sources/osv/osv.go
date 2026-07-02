package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/abdulmalik/k8sradar/core/cache"
	"github.com/abdulmalik/k8sradar/core/models"
)

const queryURL = "https://api.osv.dev/v1/query"

type Client struct {
	HTTP *http.Client
}

func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 60 * time.Second}}
}

type queryRequest struct {
	Package packageRef `json:"package"`
	Version string     `json:"version"`
}

type packageRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type queryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

type Vulnerability struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Details  string     `json:"details"`
	Aliases  []string   `json:"aliases"`
	Severity []Severity `json:"severity"`
	Affected []Affected `json:"affected"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type Finding struct {
	OSVID            string
	CVEIDs           []string
	Summary          string
	CVSSScore        float64
	CVSSVector       string
	FixedIn          string
	Component        string
	InstalledVersion string
	Ecosystem        string
	Package          string
	Asset            string // source asset name; empty if from a k8s provider component
}

func (c *Client) QueryBatch(ctx context.Context, db *cache.DB, queries []models.OSVQuery) ([]Finding, error) {
	var (
		mu       sync.Mutex
		findings []Finding
		wg       sync.WaitGroup
		errCh    = make(chan error, len(queries))
	)

	for _, q := range queries {
		if q.Version == "" {
			continue
		}
		wg.Add(1)
		go func(q models.OSVQuery) {
			defer wg.Done()
			f, err := c.queryOne(ctx, db, q)
			if err != nil {
				errCh <- err
				return
			}
			mu.Lock()
			findings = append(findings, f...)
			mu.Unlock()
		}(q)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}
	return dedupeFindings(findings), nil
}

func (c *Client) queryOne(ctx context.Context, db *cache.DB, q models.OSVQuery) ([]Finding, error) {
	raw, ok, err := db.GetOSVCache(ctx, q.Ecosystem, q.Package, q.Version)
	if err != nil {
		log.Printf("osv cache read: %v", err)
		ok = false
	}
	if ok {
		return parseCached(raw, q)
	}

	body, err := json.Marshal(queryRequest{
		Package: packageRef{Name: q.Package, Ecosystem: q.Ecosystem},
		Version: q.Version,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, queryURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv status: %s", resp.Status)
	}

	var qr queryResponse
	if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
		return nil, fmt.Errorf("decode osv: %w", err)
	}

	rawBytes, _ := json.Marshal(qr)
	if err := db.SetOSVCache(ctx, q.Ecosystem, q.Package, q.Version, string(rawBytes)); err != nil {
		log.Printf("osv cache write: %v", err)
	}

	var findings []Finding
	for _, v := range qr.Vulns {
		findings = append(findings, toFinding(v, q))
	}
	return findings, nil
}

func parseCached(raw string, q models.OSVQuery) ([]Finding, error) {
	var qr queryResponse
	if err := json.Unmarshal([]byte(raw), &qr); err != nil {
		return nil, err
	}
	var findings []Finding
	for _, v := range qr.Vulns {
		findings = append(findings, toFinding(v, q))
	}
	return findings, nil
}

func toFinding(v Vulnerability, q models.OSVQuery) Finding {
	cveIDs := extractCVEIDs(v)
	desc := v.Summary
	if desc == "" {
		desc = v.Details
	}
	score, vector := parseSeverity(v.Severity)
	return Finding{
		OSVID:            v.ID,
		CVEIDs:           cveIDs,
		Summary:          desc,
		CVSSScore:        score,
		CVSSVector:       vector,
		FixedIn:          extractFixedIn(v),
		Component:        q.Component,
		InstalledVersion: q.Version,
		Ecosystem:        q.Ecosystem,
		Package:          q.Package,
		Asset:            q.Asset,
	}
}

func extractCVEIDs(v Vulnerability) []string {
	var ids []string
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			ids = append(ids, a)
		}
	}
	if strings.HasPrefix(v.ID, "CVE-") {
		ids = append(ids, v.ID)
	}
	if len(ids) == 0 {
		ids = append(ids, v.ID)
	}
	return ids
}

func parseSeverity(sev []Severity) (score float64, vector string) {
	for _, s := range sev {
		if s.Type != "CVSS_V3" && s.Type != "CVSS_V4" {
			continue
		}
		raw := s.Score
		if idx := strings.Index(raw, "/AV:"); idx >= 0 {
			vector = raw[idx+1:]
		} else if strings.HasPrefix(raw, "CVSS:") {
			parts := strings.SplitN(raw, "/", 2)
			if len(parts) == 2 {
				vector = parts[1]
			}
		}
	}
	return score, vector
}

func extractFixedIn(v Vulnerability) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && e.Fixed != "0" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func dedupeFindings(in []Finding) []Finding {
	seen := make(map[string]struct{})
	var out []Finding
	for _, f := range in {
		key := f.OSVID + "|" + f.Component + "|" + f.InstalledVersion
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}
