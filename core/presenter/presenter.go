package presenter

import (
	"fmt"
	"io"
	"time"

	"github.com/abdulmalik/k8sradar/core/cvss"
	"github.com/abdulmalik/k8sradar/core/models"
)

// Presenter writes a ScanReport to an io.Writer.
type Presenter interface {
	Name() string
	Extension() string
	ContentType() string
	// Present renders the report. The implementation must not close the writer.
	Present(w io.Writer, report models.ScanReport) error
}

// New returns a Presenter by format name.
func New(format string) (Presenter, error) {
	switch format {
	case "table":
		return Table{}, nil
	case "json":
		return JSON{}, nil
	case "txt":
		return TXT{}, nil
	case "sarif":
		return SARIF{}, nil
	case "html":
		return HTML{}, nil
	default:
		return nil, fmt.Errorf("unknown output format: %q (supported: table, json, txt, sarif, html)", format)
	}
}

// NewMany returns Presenters for each requested format.
func NewMany(formats []string) ([]Presenter, error) {
	out := make([]Presenter, 0, len(formats))
	seen := map[string]bool{}
	for _, f := range formats {
		if f == "" {
			continue
		}
		if seen[f] {
			continue
		}
		seen[f] = true
		p, err := New(f)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// BuildReport creates a ScanReport with timestamp and summary counts.
func BuildReport(input models.ClusterInput, results []models.EnrichedCVE, gate string) models.ScanReport {
	if results == nil {
		results = []models.EnrichedCVE{}
	}

	summary := models.ReportSummary{
		Total:          len(results),
		SeverityCounts: map[string]int{},
		Gate:           gate,
	}

	for _, r := range results {
		if r.Severity == "" {
			r.Severity = "Unknown"
		}
		summary.SeverityCounts[r.Severity]++
		if r.InKEV {
			summary.KEVCount++
		}
		if r.EPSSScore > summary.MaxEPSS {
			summary.MaxEPSS = r.EPSSScore
			summary.MaxEPSSPercentile = r.EPSSPercentile
		}
	}

	if gate != "" {
		threshold := cvss.SeverityRank(gate)
		for _, r := range results {
			if cvss.SeverityRank(r.Severity) >= threshold {
				summary.GateBreached = true
				break
			}
		}
	}

	return models.ScanReport{
		ScannedAt: time.Now().UTC(),
		Input:     input,
		Results:   results,
		Summary:   summary,
	}
}

// HasNonTable returns true if any presenter writes to a file.
func HasNonTable(ps []Presenter) bool {
	for _, p := range ps {
		if p.Name() != "table" {
			return true
		}
	}
	return false
}

// FilePresenters returns presenters that write files (excludes table).
func FilePresenters(ps []Presenter) []Presenter {
	out := make([]Presenter, 0, len(ps))
	for _, p := range ps {
		if p.Name() != "table" {
			out = append(out, p)
		}
	}
	return out
}

// truncate shortens a string to at most n bytes, adding an ellipsis if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
