package presenter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abdulmalik/k8sradar/core/models"
)

func sampleReport() models.ScanReport {
	return models.ScanReport{
		Input: models.ClusterInput{
			Provider:   models.ProviderEKS,
			K8sVersion: "1.31",
		},
		Results: []models.EnrichedCVE{
			{
				ID:               "CVE-2024-0001",
				Description:      "Test vulnerability",
				CVSSScore:        9.8,
				Severity:         "Critical",
				EPSSScore:        0.5,
				EPSSPercentile:   0.9,
				Component:        "CoreDNS",
				InstalledVersion: "1.11.1",
				FixedIn:          "1.14.3",
				RemoteExploitable: true,
				InKEV:            true,
			},
		},
		Summary: models.ReportSummary{Gate: "High"},
	}
}

func TestNew(t *testing.T) {
	for _, name := range []string{"table", "json", "txt", "sarif", "html"} {
		p, err := New(name)
		if err != nil {
			t.Fatalf("new %s: %v", name, err)
		}
		if p.Name() != name {
			t.Errorf("name: got %q, want %q", p.Name(), name)
		}
	}
}

func TestNewUnknown(t *testing.T) {
	_, err := New("csv")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestJSONPresenter(t *testing.T) {
	var buf bytes.Buffer
	report := BuildReport(sampleReport().Input, sampleReport().Results, "High")
	if err := (JSON{}).Present(&buf, report); err != nil {
		t.Fatalf("present: %v", err)
	}
	var decoded models.ScanReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Summary.Total != 1 {
		t.Errorf("total: got %d", decoded.Summary.Total)
	}
	if !decoded.Summary.GateBreached {
		t.Error("expected gate breached")
	}
}

func TestTXTPresenter(t *testing.T) {
	var buf bytes.Buffer
	report := BuildReport(sampleReport().Input, sampleReport().Results, "")
	if err := (TXT{}).Present(&buf, report); err != nil {
		t.Fatalf("present: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "CVE-2024-0001") {
		t.Error("missing CVE ID")
	}
	if !strings.Contains(out, "Critical") {
		t.Error("missing severity")
	}
}

func TestTablePresenter(t *testing.T) {
	var buf bytes.Buffer
	report := BuildReport(sampleReport().Input, sampleReport().Results, "")
	if err := (Table{}).Present(&buf, report); err != nil {
		t.Fatalf("present: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "CVE") || !strings.Contains(out, "CVE-2024-0001") {
		t.Error("expected table with CVE column and finding")
	}
}

func TestHTMLPresenter(t *testing.T) {
	var buf bytes.Buffer
	report := BuildReport(sampleReport().Input, sampleReport().Results, "")
	if err := (HTML{}).Present(&buf, report); err != nil {
		t.Fatalf("present: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("missing DOCTYPE")
	}
	if !strings.Contains(out, "CVE-2024-0001") {
		t.Error("missing finding")
	}
}

func TestSARIFPresenter(t *testing.T) {
	var buf bytes.Buffer
	report := BuildReport(sampleReport().Input, sampleReport().Results, "")
	if err := (SARIF{}).Present(&buf, report); err != nil {
		t.Fatalf("present: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"version": "2.1.0"`) {
		t.Error("missing SARIF version")
	}
	if !strings.Contains(out, "CVE-2024-0001") {
		t.Error("missing finding")
	}
}

func TestBuildReportSummary(t *testing.T) {
	report := BuildReport(models.ClusterInput{}, []models.EnrichedCVE{
		{Severity: "Critical", InKEV: true, EPSSScore: 0.1},
		{Severity: "High"},
	}, "High")
	if report.Summary.Total != 2 {
		t.Errorf("total: got %d", report.Summary.Total)
	}
	if report.Summary.KEVCount != 1 {
		t.Errorf("kev: got %d", report.Summary.KEVCount)
	}
	if report.Summary.SeverityCounts["Critical"] != 1 {
		t.Errorf("severity counts: %+v", report.Summary.SeverityCounts)
	}
	if !report.Summary.GateBreached {
		t.Error("expected gate breached")
	}
}
