# k8sradar

CLI vulnerability radar for Kubernetes platforms and generic software assets.

k8sradar scans provider component versions or arbitrary OSV packages and enriches findings with CVSS severity, EPSS exploit probability, and CISA KEV status. It is modelled on Grype and built for CI/CD: pass your stack, get a report, and gate the build.

## Install

Download a release binary or build from source:

```bash
go install github.com/saintmalik/k8sradar/cli/cmd/k8sradar@latest
```

## Quick start

```bash
# Default console table for an EKS cluster
k8sradar eks --k8s-version 1.31

# Read a stack from a config file and produce JSON + SARIF
k8sradar -f stack.yaml -o json,sarif --output-dir ./reports

# Scan arbitrary software assets (ecosystem aliases deb→Debian, go→Go)
k8sradar --asset go/k8s.io/kubernetes@1.31.2 --asset deb/nginx@1.25.3

# Product shorthands for common infra (no K8s provider needed)
k8sradar --asset openvpn@2.6.12 --asset wireguard@1.0.20210914 -o table,json
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
| `--asset ecosystem/package@version` | Generic asset; aliases `deb`→Debian, `go`→Go; also `product@version` shorthands like `openvpn@2.6.12`; repeatable |
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

### Non-Kubernetes assets

Scan any OSV-tracked package with `ecosystem/package@version`. Common ecosystem aliases work: `deb`, `go`, `npm`, `pypi`, `alpine`, `rpm`.

Product shorthands (no ecosystem prefix):

| Shorthand | What it scans |
|-----------|----------------|
| `openvpn@VERSION` | Debian openvpn |
| `wireguard@VERSION` | Debian wireguard-tools + wireguard-dkms |
| `nginx@VERSION` | Debian + Alpine nginx |
| `postgresql@VERSION` | Debian postgresql |
| `redis@VERSION` | Debian redis-server |
| `openssl@VERSION` | Debian openssl |

**Slack / Jira Cloud** are SaaS products — OSV does not version them. For Slack we scan the Node SDK (`npm/@slack/web-api`) as a best-effort proxy. For self-hosted Atlassian products, use explicit `--asset deb/PACKAGE@VERSION` if your distro packages them.

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

## License

Copyright (c) 2026 Abdulmalik Salawu.

k8sradar is licensed under the **GNU Affero General Public License v3.0** (AGPLv3).

You are free to fork, use, and modify this software, including for commercial use. However, any derivative work must also be licensed under AGPLv3, and if you make the software available over a network (e.g. as a hosted service), you must make your complete source code available to all users of that service.

This ensures k8sradar and all derivatives remain open-source. See [LICENSE](LICENSE) for the full text.
