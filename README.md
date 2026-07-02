# k8sradar

CLI vulnerability radar for Kubernetes platforms and generic software assets.

k8sradar scans provider component versions or arbitrary OSV packages and enriches findings with CVSS severity, EPSS exploit probability, and CISA KEV status. It is modelled on Grype and built for CI/CD: pass your stack, get a report, and gate the build.

## Install

Download a release binary or build from source:

```bash
go install github.com/abdulmalik/k8sradar/cli/cmd/k8sradar@latest
```

## Quick start

```bash
# Default console table for an EKS cluster
k8sradar eks --k8s-version 1.31

# Read a stack from a config file and produce JSON + SARIF
k8sradar -f stack.yaml -o json,sarif --output-dir ./reports

# Scan arbitrary software assets
k8sradar --asset go/k8s.io/kubernetes@1.31.2 --asset deb/nginx@1.25.3
```

## Usage

```text
k8sradar [provider] [flags]
```

Provider can be passed as a positional argument (`k8sradar eks`) or via `--provider`. If you only want to scan generic assets, omit the provider.

### Flags

| Flag | Description |
|------|-------------|
| `[provider]` | Positional provider, e.g. `eks`, `gke`, `aks` |
| `-p, --provider` | Provider (alternative to positional) |
| `-v, --k8s-version` | Kubernetes version |
| `-n, --node-os` | Node operating system |
| `-c, --component name=version` | Component override; repeatable |
| `--asset ecosystem/package@version` | Generic asset; also accepts `pkg:type/name@version`; repeatable |
| `-f, --config` | YAML/JSON config file; `-` reads stdin |
| `-o, --output` | Output formats: `table`, `json`, `txt`, `sarif`, `html` (default `table`) |
| `--output-dir` | Directory for generated report files (default `.`) |
| `-F, --output-file` | Explicit file for a single file-format output |
| `--fail-on` | Exit 1 if findings at/above severity: `Critical`, `High`, `Medium`, `Low` |
| `--slack-webhook` | Slack incoming webhook URL |
| `--slack-token` | Slack bot OAuth token |
| `--slack-channel` | Slack channel ID (required with token) |
| `--slack-disable-file` | Skip Slack file upload even with token |
| `--sync` | Run a cache sync before scanning |
| `--db-path` | Path to SQLite cache (default `./data/k8sradar.db`) |
| `--manifest-dir` | Provider manifest directory |
| `--nvd-api-key` | Optional NVD API key |

### Config file

```yaml
provider: eks
k8s_version: "1.31"
node_os: al2023
components:
  - name: kubernetes
    version: "1.31.2"

assets:
  - name: nginx
    package: nginx
    ecosystem: Debian
    version: "1.25.3"

output: [json, html]
output_dir: ./reports
fail_on: High

slack:
  webhook: https://hooks.slack.com/services/...
  token: xoxb-...
  channel: C1234567890
```

CLI flags override config file values. Assets can be passed without a provider.

## Report formats

| Format | Description |
|--------|-------------|
| `table` | Default console table |
| `json` | Full scan report with summary and findings |
| `txt` | Human-readable plain-text summary |
| `sarif` | SARIF 2.1.0 for GitHub Code Scanning and CI |
| `html` | Self-contained HTML report (no external assets) |

Multiple formats can be requested at once: `-o json,html,sarif,txt`.

## Viewing HTML reports

```bash
# Serve a single report
k8sradar serve --file ./reports/k8sradar-report.html

# Serve a directory of reports
k8sradar serve --dir ./reports
```

This is a lightweight static file server for locally viewing generated HTML. It is not the deployed web UI.

## Slack integration

- **Webhook only**: posts a rich summary block. Report files are still written locally.
- **Bot token + channel ID**: posts the summary and uploads each generated report file.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan succeeded and gate passed |
| `1` | Vulnerabilities found at/above `--fail-on` severity |
| `2` | Runtime error |

## Environment variables

| Variable | Description |
|----------|-------------|
| `K8SRADAR_OUTPUT` | Default output format list |
| `K8SRADAR_OUTPUT_DIR` | Default report directory |
| `K8SRADAR_FAIL_ON` | Default `--fail-on` severity |
| `K8SRADAR_SLACK_WEBHOOK` | Slack webhook URL |
| `K8SRADAR_SLACK_TOKEN` | Slack bot OAuth token |
| `K8SRADAR_SLACK_CHANNEL` | Slack channel ID |
| `DB_PATH` | SQLite cache path (default `./data/k8sradar.db`) |
| `MANIFEST_DIR` | Provider manifest directory |
| `NVD_API_KEY` | Optional NVD API key |

## CI example

```yaml
- name: Scan EKS stack
  run: k8sradar eks --k8s-version 1.31 --fail-on High -o sarif --output-filereport.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```

## Development

```bash
# Build the CLI binary
make build

# Run tests
go test ./...
```
