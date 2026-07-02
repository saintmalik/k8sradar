package exit

import (
	"github.com/abdulmalik/k8sradar/core/cvss"
	"github.com/abdulmalik/k8sradar/core/models"
)

// Exit codes used by the k8sradar CLI.
const (
	OK           = 0
	GateFailed   = 1
	RuntimeError = 2
)

// GateBreached returns true if any result meets or exceeds the threshold
// severity. Unknown severity never breaches a gate.
func GateBreached(results []models.EnrichedCVE, threshold string) bool {
	rank := cvss.SeverityRank(threshold)
	if rank <= 0 {
		return false
	}
	for _, r := range results {
		if cvss.SeverityRank(r.Severity) >= rank {
			return true
		}
	}
	return false
}

// Code returns the appropriate exit code for a scan outcome.
func Code(err error, gate string, results []models.EnrichedCVE) int {
	if err != nil {
		return RuntimeError
	}
	if gate != "" && GateBreached(results, gate) {
		return GateFailed
	}
	return OK
}
