package exit

import (
	"testing"

	"github.com/abdulmalik/k8sradar/core/models"
)

func TestGateBreached(t *testing.T) {
	results := []models.EnrichedCVE{
		{Severity: "Critical", CVSSScore: 9.8},
		{Severity: "Medium", CVSSScore: 5.0},
	}

	if !GateBreached(results, "High") {
		t.Error("expected gate breached for High")
	}
	if !GateBreached(results, "Critical") {
		t.Error("expected gate breached for Critical")
	}
	if GateBreached(results, "") {
		t.Error("empty gate should not breach")
	}
}

func TestCode(t *testing.T) {
	if Code(nil, "High", []models.EnrichedCVE{{Severity: "Medium"}}) != OK {
		t.Error("expected OK when gate not breached")
	}
	if Code(nil, "High", []models.EnrichedCVE{{Severity: "Critical"}}) != GateFailed {
		t.Error("expected GateFailed")
	}
	if Code(errSample(), "", nil) != RuntimeError {
		t.Error("expected RuntimeError on error")
	}
}

func errSample() error {
	return errSentinel{}
}

type errSentinel struct{}

func (errSentinel) Error() string { return "sample" }
