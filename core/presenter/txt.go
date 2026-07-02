package presenter

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/abdulmalik/k8sradar/core/models"
)

// TXT writes a human-readable plain-text report.
type TXT struct{}

func (TXT) Name() string        { return "txt" }
func (TXT) Extension() string   { return ".txt" }
func (TXT) ContentType() string { return "text/plain; charset=utf-8" }

func (TXT) Present(w io.Writer, report models.ScanReport) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "k8sradar scan report\n")
	fmt.Fprintf(b, "Scanned at: %s\n", report.ScannedAt.Format("2006-01-02 15:04:05 UTC"))

	if report.Input.Provider != "" {
		fmt.Fprintf(b, "Provider:   %s\n", report.Input.Provider.Label())
	}
	if report.Input.K8sVersion != "" {
		fmt.Fprintf(b, "K8s version: %s\n", report.Input.K8sVersion)
	}
	if report.Input.NodeOS != "" {
		fmt.Fprintf(b, "Node OS:    %s\n", report.Input.NodeOS)
	}

	b.WriteString("\nAssets:\n")
	if len(report.Input.Components) > 0 {
		for _, c := range report.Input.Components {
			if c.Version == "" {
				continue
			}
			fmt.Fprintf(b, "  - %s: %s\n", c.Name, c.Version)
		}
	}
	if len(report.Input.Assets) > 0 {
		for _, a := range report.Input.Assets {
			label := a.Name
			if label == "" {
				label = a.Package
			}
			fmt.Fprintf(b, "  - %s (%s/%s): %s\n", label, a.Ecosystem, a.Package, a.Version)
		}
	}
	if len(report.Input.Components) == 0 && len(report.Input.Assets) == 0 {
		b.WriteString("  (none specified)\n")
	}

	fmt.Fprintf(b, "\nSummary:\n")
	fmt.Fprintf(b, "  Total CVEs: %d\n", report.Summary.Total)
	fmt.Fprintf(b, "  KEV:        %d\n", report.Summary.KEVCount)
	if report.Summary.MaxEPSS > 0 {
		fmt.Fprintf(b, "  Max EPSS:   %.4f (%.2f%% percentile)\n", report.Summary.MaxEPSS, report.Summary.MaxEPSSPercentile*100)
	}

	b.WriteString("  Severity breakdown:\n")
	order := []string{"Critical", "High", "Medium", "Low", "Unknown"}
	for _, sev := range order {
		if n := report.Summary.SeverityCounts[sev]; n > 0 || sev == "Critical" || sev == "High" {
			fmt.Fprintf(b, "    %s: %d\n", sev, n)
		}
	}

	if report.Summary.Gate != "" {
		if report.Summary.GateBreached {
			fmt.Fprintf(b, "\nFAIL: gate breached (--fail-on %s)\n", report.Summary.Gate)
		} else {
			fmt.Fprintf(b, "\nPASS: gate not breached (--fail-on %s)\n", report.Summary.Gate)
		}
	}

	if len(report.Results) == 0 {
		b.WriteString("\nNo findings.\n")
		_, err := io.Copy(w, strings.NewReader(b.String()))
		return err
	}

	b.WriteString("\nFindings:\n")
	sorted := make([]models.EnrichedCVE, len(report.Results))
	copy(sorted, report.Results)
	sortBySeverityThenEPSS(sorted)

	for _, r := range sorted {
		fmt.Fprintf(b, "\n  %s | %s | CVSS %.1f | EPSS %.4f | %s\n", r.ID, r.Severity, r.CVSSScore, r.EPSSScore, r.Component)
		if r.Description != "" {
			fmt.Fprintf(b, "  %s\n", truncate(r.Description, 120))
		}
		if r.FixedIn != "" {
			fmt.Fprintf(b, "  Fixed in: %s\n", r.FixedIn)
		}
		if r.InKEV {
			b.WriteString("  ⭐ Known Exploited Vulnerability\n")
		}
		if r.RemoteExploitable {
			b.WriteString("  🌐 Remotely exploitable\n")
		}
	}

	_, err := io.Copy(w, strings.NewReader(b.String()))
	return err
}

func sortBySeverityThenEPSS(results []models.EnrichedCVE) {
	// stable severity ordering is handled by the map below
	rank := map[string]int{"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0, "": 0}
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] > rank[b.Severity]
		}
		if a.EPSSScore != b.EPSSScore {
			return a.EPSSScore > b.EPSSScore
		}
		return a.CVSSScore > b.CVSSScore
	})
}
