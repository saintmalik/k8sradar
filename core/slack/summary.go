package slack

import (
	"fmt"
	"maps"

	"github.com/abdulmalik/k8sradar/core/cvss"
	"github.com/abdulmalik/k8sradar/core/models"
)

// SummaryFromReport builds a Slack summary from a scan report.
// maxFindings caps the number of top CVE lines included in the message.
func SummaryFromReport(report models.ScanReport, maxFindings int) Summary {
	provider := ""
	if report.Input.Provider != "" {
		provider = report.Input.Provider.Label()
	}

	counts := map[string]int{}
	maps.Copy(counts, report.Summary.SeverityCounts)

	summary := Summary{
		Title:             fmt.Sprintf("k8sradar scan: %d CVEs", report.Summary.Total),
		ScannedAt:         report.ScannedAt.Format("2006-01-02 15:04 UTC"),
		Provider:          provider,
		K8sVersion:        report.Input.K8sVersion,
		TotalCVEs:         report.Summary.Total,
		KEVCount:          report.Summary.KEVCount,
		MaxEPSS:           report.Summary.MaxEPSS,
		MaxEPSSPercentile: report.Summary.MaxEPSSPercentile,
		SeverityCounts:    counts,
		Gate:              report.Summary.Gate,
		GateBreached:      report.Summary.GateBreached,
		TopFindings:       topFindingLines(report.Results, maxFindings),
	}

	if summary.Gate != "" {
		if summary.GateBreached {
			summary.Title += fmt.Sprintf(" | gate %s breached", summary.Gate)
		} else {
			summary.Title += fmt.Sprintf(" | gate %s passed", summary.Gate)
		}
	}

	return summary
}

func topFindingLines(results []models.EnrichedCVE, max int) []FindingLine {
	if max <= 0 {
		max = 5
	}

	// Sort by severity rank, then EPSS, then CVSS.
	sorted := make([]models.EnrichedCVE, len(results))
	copy(sorted, results)
	for i := range sorted {
		for j := i + 1; j < len(sorted); j++ {
			a, b := sorted[i], sorted[j]
			ra, rb := cvss.SeverityRank(a.Severity), cvss.SeverityRank(b.Severity)
			if ra < rb || (ra == rb && a.EPSSScore < b.EPSSScore) || (ra == rb && a.EPSSScore == b.EPSSScore && a.CVSSScore < b.CVSSScore) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	out := make([]FindingLine, 0, max)
	for i, r := range sorted {
		if i >= max {
			break
		}
		out = append(out, FindingLine{
			ID:        r.ID,
			Severity:  r.Severity,
			Component: r.Component,
			EPSS:      r.EPSSScore,
			InKEV:     r.InKEV,
		})
	}
	return out
}
