package presenter

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/abdulmalik/k8sradar/core/models"
)

// Table writes a console-friendly findings table.
type Table struct{}

func (Table) Name() string        { return "table" }
func (Table) Extension() string { return "" }
func (Table) ContentType() string { return "text/plain; charset=utf-8" }

func (Table) Present(w io.Writer, report models.ScanReport) error {
	b := &strings.Builder{}

	if report.Input.Provider != "" {
		fmt.Fprintf(b, "Provider: %s\n", report.Input.Provider.Label())
	}
	if report.Input.K8sVersion != "" {
		fmt.Fprintf(b, "K8s version: %s\n", report.Input.K8sVersion)
	}
	fmt.Fprintf(b, "CVEs: %d | KEV: %d | Scanned: %s\n\n", report.Summary.Total, report.Summary.KEVCount, report.ScannedAt.Format("2006-01-02 15:04 UTC"))

	if len(report.Results) == 0 {
		b.WriteString("No findings.\n")
		_, err := io.Copy(w, strings.NewReader(b.String()))
		return err
	}

	tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CVE\tSEVERITY\tEPSS\tKEV\tREMOTE\tCOMPONENT\tINSTALLED\tFIXED IN")
	for _, r := range report.Results {
		kev := "-"
		if r.InKEV {
			kev = "Yes"
		}
		remote := "-"
		if r.RemoteExploitable {
			remote = "Yes"
		}
		fixed := r.FixedIn
		if fixed == "" {
			fixed = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%.4f\t%s\t%s\t%s\t%s\t%s\n",
			r.ID, r.Severity, r.EPSSScore, kev, remote, r.Component, r.InstalledVersion, fixed)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if report.Summary.Gate != "" {
		if report.Summary.GateBreached {
			fmt.Fprintf(b, "\nGate breached: --fail-on %s\n", report.Summary.Gate)
		} else {
			fmt.Fprintf(b, "\nGate passed: --fail-on %s\n", report.Summary.Gate)
		}
	}

	_, err := io.Copy(w, strings.NewReader(b.String()))
	return err
}
