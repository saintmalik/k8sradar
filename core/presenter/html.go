package presenter

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/abdulmalik/k8sradar/core/models"
)

// HTML writes a self-contained HTML report.
type HTML struct{}

func (HTML) Name() string        { return "html" }
func (HTML) Extension() string   { return ".html" }
func (HTML) ContentType() string { return "text/html; charset=utf-8" }

func (HTML) Present(w io.Writer, report models.ScanReport) error {
	_, err := io.WriteString(w, renderHTML(report))
	return err
}

func renderHTML(report models.ScanReport) string {
	b := &strings.Builder{}

	fmt.Fprintln(b, `<!DOCTYPE html>`)
	fmt.Fprintln(b, `<html lang="en">`)
	fmt.Fprintln(b, `<head>`)
	fmt.Fprintln(b, `  <meta charset="UTF-8">`)
	fmt.Fprintln(b, `  <meta name="viewport" content="width=device-width, initial-scale=1.0">`)
	fmt.Fprintf(b, "  <title>k8sradar report — %s</title>\n", report.ScannedAt.Format("2006-01-02"))
	fmt.Fprintln(b, `  <style>`)
	fmt.Fprintln(b, htmlStyles())
	fmt.Fprintln(b, `  </style>`)
	fmt.Fprintln(b, `</head>`)
	fmt.Fprintln(b, `<body>`)
	fmt.Fprintln(b, `  <div class="page">`)
	fmt.Fprintln(b, `    <header class="header">`)
	fmt.Fprintln(b, `      <div class="container">`)
	fmt.Fprintln(b, `        <h1>k8sradar</h1>`)
	fmt.Fprintf(b, `        <p class="muted">Scanned at %s</p>`+"\n", report.ScannedAt.Format(time.RFC3339))
	fmt.Fprintln(b, `      </div>`)
	fmt.Fprintln(b, `    </header>`)
	fmt.Fprintln(b, `    <main class="container">`)

	renderSummary(b, report)
	renderFindingsTable(b, report)

	fmt.Fprintln(b, `    </main>`)
	fmt.Fprintln(b, `  </div>`)
	fmt.Fprintln(b, `</body>`)
	fmt.Fprintln(b, `</html>`)

	return b.String()
}

func renderSummary(b *strings.Builder, report models.ScanReport) {
	fmt.Fprintln(b, `      <section class="card">`)
	fmt.Fprintln(b, `        <div class="summary-grid">`)
	fmt.Fprintf(b, "          <div class=\"stat\"><span class=\"stat-label\">Total CVEs</span><span class=\"stat-value\">%d</span></div>\n", report.Summary.Total)
	fmt.Fprintf(b, "          <div class=\"stat\"><span class=\"stat-label\">KEV</span><span class=\"stat-value\">%d</span></div>\n", report.Summary.KEVCount)
	fmt.Fprintf(b, "          <div class=\"stat\"><span class=\"stat-label\">Max EPSS</span><span class=\"stat-value\">%.4f</span></div>\n", report.Summary.MaxEPSS)
	if report.Input.Provider != "" {
		fmt.Fprintf(b, "          <div class=\"stat\"><span class=\"stat-label\">Provider</span><span class=\"stat-value\">%s</span></div>\n", html.EscapeString(report.Input.Provider.Label()))
	}
	if report.Input.K8sVersion != "" {
		fmt.Fprintf(b, "          <div class=\"stat\"><span class=\"stat-label\">K8s</span><span class=\"stat-value\">%s</span></div>\n", html.EscapeString(report.Input.K8sVersion))
	}
	fmt.Fprintln(b, `        </div>`)

	order := []string{"Critical", "High", "Medium", "Low", "Unknown"}
	fmt.Fprintln(b, `        <div class="severity-bar">`)
	for _, sev := range order {
		n := report.Summary.SeverityCounts[sev]
		fmt.Fprintf(b, "          <div class=\"severity-pill severity-%s\">%s: %d</div>\n", strings.ToLower(sev), sev, n)
	}
	fmt.Fprintln(b, `        </div>`)

	if report.Summary.Gate != "" {
		if report.Summary.GateBreached {
			fmt.Fprintf(b, "        <p class=\"gate gate-fail\">Gate breached: --fail-on %s</p>\n", html.EscapeString(report.Summary.Gate))
		} else {
			fmt.Fprintf(b, "        <p class=\"gate gate-pass\">Gate passed: --fail-on %s</p>\n", html.EscapeString(report.Summary.Gate))
		}
	}
	fmt.Fprintln(b, `      </section>`)
}

func renderFindingsTable(b *strings.Builder, report models.ScanReport) {
	if len(report.Results) == 0 {
		fmt.Fprintln(b, `      <section class="card empty-state"><h2>No findings</h2></section>`)
		return
	}

	fmt.Fprintln(b, `      <section class="card">`)
	fmt.Fprintln(b, `        <div class="table-scroll">`)
	fmt.Fprintln(b, `          <table class="findings">`)
	fmt.Fprintln(b, `            <thead>`)
	fmt.Fprintln(b, `              <tr>`)
	fmt.Fprintln(b, `                <th>CVE</th>`)
	fmt.Fprintln(b, `                <th>Severity</th>`)
	fmt.Fprintln(b, `                <th>EPSS</th>`)
	fmt.Fprintln(b, `                <th>KEV</th>`)
	fmt.Fprintln(b, `                <th>Remote</th>`)
	fmt.Fprintln(b, `                <th>Component</th>`)
	fmt.Fprintln(b, `                <th>Installed</th>`)
	fmt.Fprintln(b, `                <th>Fixed in</th>`)
	fmt.Fprintln(b, `              </tr>`)
	fmt.Fprintln(b, `            </thead>`)
	fmt.Fprintln(b, `            <tbody>`)
	for _, r := range report.Results {
		fmt.Fprintln(b, `              <tr>`)
		fmt.Fprintf(b, "                <td><a class=\"cve-link\" href=\"%s\" target=\"_blank\" rel=\"noopener\">%s</a><p class=\"cve-desc\">%s</p></td>\n",
			cveURL(r.ID), html.EscapeString(r.ID), html.EscapeString(truncate(r.Description, 120)))
		fmt.Fprintf(b, "                <td><span class=\"badge severity-%s\">%s %.1f</span></td>\n", strings.ToLower(r.Severity), r.Severity, r.CVSSScore)
		fmt.Fprintf(b, "                <td>%.4f</td>\n", r.EPSSScore)
		kev := "-"
		if r.InKEV {
			kev = `<span class="kev-badge">KEV</span>`
		}
		fmt.Fprintf(b, "                <td>%s</td>\n", kev)
		remote := "-"
		if r.RemoteExploitable {
			remote = "Yes"
		}
		fmt.Fprintf(b, "                <td>%s</td>\n", remote)
		fmt.Fprintf(b, "                <td>%s</td>\n", html.EscapeString(r.Component))
		fmt.Fprintf(b, "                <td><code>%s</code></td>\n", html.EscapeString(r.InstalledVersion))
		fixed := r.FixedIn
		if fixed == "" {
			fixed = "-"
		}
		fmt.Fprintf(b, "                <td><code>%s</code></td>\n", html.EscapeString(fixed))
		fmt.Fprintln(b, `              </tr>`)
	}
	fmt.Fprintln(b, `            </tbody>`)
	fmt.Fprintln(b, `          </table>`)
	fmt.Fprintln(b, `        </div>`)
	fmt.Fprintln(b, `      </section>`)
}

func cveURL(id string) string {
	if len(id) >= 4 && id[:4] == "CVE-" {
		return "https://nvd.nist.gov/vuln/detail/" + id
	}
	return "https://osv.dev/vulnerability/" + id
}

func htmlStyles() string {
	return `:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #e6edf3; --muted: #8b949e; --link: #58a6ff;
  --critical: #ff7b72; --high: #ffa657; --medium: #d29922; --low: #3fb950; --unknown: #8b949e;
  --kev: #f85149;
}
*, *::before, *::after { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; font-size: 14px; }
.page { min-height: 100vh; display: flex; flex-direction: column; }
.container { width: 100%; max-width: 1100px; margin: 0 auto; padding: 0 1.25rem; }
.header { padding: 1rem 0; border-bottom: 1px solid var(--border); margin-bottom: 1.5rem; }
.header h1 { margin: 0; font-size: 1.5rem; }
.muted { color: var(--muted); margin: 0.25rem 0 0; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.25rem; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 1rem; }
.stat { display: flex; flex-direction: column; }
.stat-label { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
.stat-value { font-size: 1.25rem; font-weight: 600; }
.severity-bar { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; }
.severity-pill { padding: 0.35rem 0.75rem; border-radius: 999px; font-size: 0.8rem; font-weight: 600; background: var(--border); }
.severity-critical { background: rgba(255,123,114,0.2); color: var(--critical); }
.severity-high { background: rgba(255,166,87,0.2); color: var(--high); }
.severity-medium { background: rgba(210,153,34,0.2); color: var(--medium); }
.severity-low { background: rgba(63,185,80,0.2); color: var(--low); }
.severity-unknown { background: rgba(139,148,158,0.2); color: var(--unknown); }
.gate { margin: 1rem 0 0; padding: 0.75rem 1rem; border-radius: 6px; font-weight: 600; }
.gate-pass { background: rgba(63,185,80,0.15); color: var(--low); }
.gate-fail { background: rgba(255,123,114,0.15); color: var(--critical); }
.table-scroll { overflow-x: auto; }
table.findings { width: 100%; border-collapse: collapse; }
table.findings th, table.findings td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
table.findings th { color: var(--muted); font-weight: 500; }
.cve-link { color: var(--link); text-decoration: none; font-weight: 500; }
.cve-desc { color: var(--muted); margin: 0.35rem 0 0; font-size: 0.8rem; }
.badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; background: var(--border); }
.kev-badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; background: rgba(248,81,73,0.2); color: var(--kev); }
code { font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, monospace; background: var(--bg); padding: 0.15rem 0.35rem; border-radius: 4px; font-size: 0.85rem; }
.empty-state { text-align: center; padding: 3rem 1rem; color: var(--muted); }
.empty-state h2 { margin: 0 0 0.5rem; color: var(--text); }`
}
