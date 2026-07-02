package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/abdulmalik/k8sradar/core/cache"
)

const baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type Client struct {
	HTTP   *http.Client
	APIKey string
}

func New(apiKey string) *Client {
	return &Client{
		HTTP:   &http.Client{Timeout: 60 * time.Second},
		APIKey: apiKey,
	}
}

var keywords = []string{
	"kubernetes",
	"kubelet",
	"coredns",
	"aws-node",
	"kube-proxy",
}

func (c *Client) SyncKeywords(ctx context.Context, db *cache.DB, maxPages int) (int, error) {
	total := 0
	for _, kw := range keywords {
		n, err := c.syncKeyword(ctx, db, kw, maxPages)
		if err != nil {
			return total, fmt.Errorf("sync keyword %q: %w", kw, err)
		}
		total += n
		c.waitRateLimit()
	}
	return total, nil
}

func (c *Client) syncKeyword(ctx context.Context, db *cache.DB, keyword string, maxPages int) (int, error) {
	startIndex := 0
	count := 0
	for page := 0; page < maxPages; page++ {
		u, _ := url.Parse(baseURL)
		q := u.Query()
		q.Set("keywordSearch", keyword)
		q.Set("resultsPerPage", "100")
		q.Set("startIndex", fmt.Sprintf("%d", startIndex))
		u.RawQuery = q.Encode()

		resp, err := c.get(ctx, u.String())
		if err != nil {
			return count, err
		}

		var payload nvdResponse
		if err := json.Unmarshal(resp, &payload); err != nil {
			return count, err
		}

		for _, item := range payload.Vulnerabilities {
			if err := upsertItem(ctx, db, item); err != nil {
				return count, err
			}
			count++
		}

		if startIndex+payload.ResultsPerPage >= payload.TotalResults {
			break
		}
		startIndex += payload.ResultsPerPage
		c.waitRateLimit()
	}
	return count, nil
}

func (c *Client) get(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("nvd %s: %s", resp.Status, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (c *Client) waitRateLimit() {
	if c.APIKey != "" {
		time.Sleep(650 * time.Millisecond)
		return
	}
	time.Sleep(6500 * time.Millisecond)
}

type nvdResponse struct {
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE cveItem `json:"cve"`
	} `json:"vulnerabilities"`
}

type cveItem struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CvssMetricV31 []struct {
			CvssData struct {
				BaseScore    float64 `json:"baseScore"`
				VectorString string `json:"vectorString"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
	} `json:"metrics"`
}

func upsertItem(ctx context.Context, db *cache.DB, item struct {
	CVE cveItem `json:"cve"`
}) error {
	c := item.CVE
	desc := ""
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	score := 0.0
	vector := ""
	if len(c.Metrics.CvssMetricV31) > 0 {
		score = c.Metrics.CvssMetricV31[0].CvssData.BaseScore
		vector = c.Metrics.CvssMetricV31[0].CvssData.VectorString
	}
	raw, _ := json.Marshal(c)
	return db.UpsertCVE(ctx, cache.CVE{
		ID:          c.ID,
		Description: desc,
		CVSSScore:   score,
		CVSSVector:  vector,
		Published:   c.Published,
	}, string(raw))
}

func (c *Client) LookupCVE(ctx context.Context, db *cache.DB, cveID string) (*cache.CVE, error) {
	if !strings.HasPrefix(cveID, "CVE-") {
		return nil, nil
	}
	if existing, _ := db.GetCVE(ctx, cveID); existing != nil && existing.CVSSScore > 0 {
		return existing, nil
	}

	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("cveId", cveID)
	u.RawQuery = q.Encode()

	resp, err := c.get(ctx, u.String())
	if err != nil {
		return nil, err
	}

	var payload nvdResponse
	if err := json.Unmarshal(resp, &payload); err != nil {
		return nil, err
	}
	if len(payload.Vulnerabilities) == 0 {
		return nil, nil
	}

	item := payload.Vulnerabilities[0]
	if err := upsertItem(ctx, db, item); err != nil {
		return nil, err
	}
	c.waitRateLimit()
	return db.GetCVE(ctx, cveID)
}

func (c *Client) EnrichCVEs(ctx context.Context, db *cache.DB, cveIDs []string) error {
	const maxLookups = 6
	looked := 0
	for _, id := range cveIDs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		if existing, _ := db.GetCVE(ctx, id); existing != nil && existing.CVSSScore > 0 {
			continue
		}
		if looked >= maxLookups {
			log.Printf("nvd: skipped remaining CVEs (cap %d per scan, rest cached on next run)", maxLookups)
			break
		}
		if _, err := c.LookupCVE(ctx, db, id); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			log.Printf("nvd lookup %s: %v", id, err)
		}
		looked++
	}
	return nil
}

func ParseCVSSVector(raw string) string {
	if strings.Contains(raw, "CVSS:3") {
		if idx := strings.Index(raw, "/AV:"); idx >= 0 {
			return raw[idx+1:]
		}
	}
	return raw
}
