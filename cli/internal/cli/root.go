package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/saintmalik/k8sradar/core/cache"
	"github.com/saintmalik/k8sradar/core/config"
	"github.com/saintmalik/k8sradar/core/exit"
	"github.com/saintmalik/k8sradar/core/input"
	"github.com/saintmalik/k8sradar/core/models"
	"github.com/saintmalik/k8sradar/core/presenter"
	"github.com/saintmalik/k8sradar/core/providers"
	"github.com/saintmalik/k8sradar/core/scan"
	slackpkg "github.com/saintmalik/k8sradar/core/slack"
	"github.com/saintmalik/k8sradar/core/sync"
	"github.com/spf13/cobra"
)

// scanFlags holds values bound by Cobra flags.
type scanFlags struct {
	provider        string
	k8sVersion      string
	nodeOS          string
	components      []models.ComponentVersion
	assets          []models.Asset
	configPath      string
	outputFormats   []string
	outputDir       string
	outputFile      string
	failOn          string
	slackWebhook    string
	slackToken      string
	slackChannel    string
	slackDisableFile bool
	dbPath          string
	manifestDir     string
	nvdAPIKey       string
	sync            bool
}

var flags scanFlags

// RootCmd is the exposed Cobra root command.
var RootCmd = &cobra.Command{
	Use:   "k8sradar [provider]",
	Short: "Unified Kubernetes CVE radar",
	Long: `k8sradar scans Kubernetes provider component versions and generic software
assets against OSV and enriches findings with CVSS, EPSS, and CISA KEV data.`,
	Example: `  k8sradar eks --k8s-version 1.31
  k8sradar -f stack.yaml -o json,sarif
  k8sradar --asset go/k8s.io/kubernetes@1.31.2 --asset deb/nginx@1.25.3`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	cfg := config.Load()

	RootCmd.Flags().StringVarP(&flags.provider, "provider", "p", "", "Kubernetes provider (e.g. eks, gke, aks)")
	RootCmd.Flags().StringVarP(&flags.k8sVersion, "k8s-version", "v", "", "Kubernetes version")
	RootCmd.Flags().StringVarP(&flags.nodeOS, "node-os", "n", "", "Node operating system")
	RootCmd.Flags().VarP(newComponentFlagValue(&flags.components), "component", "c", "Component override (name=version); repeatable")
	RootCmd.Flags().Var(newAssetFlagValue(&flags.assets), "asset", "Generic asset (ecosystem/package@version or pkg:type/name@version); repeatable")
	RootCmd.Flags().StringVarP(&flags.configPath, "config", "f", "", "Stack config file; '-' reads from stdin")
	RootCmd.Flags().StringVarP(&flags.outputFile, "output-file", "F", "", "Explicit report file (single non-table output)")
	RootCmd.Flags().StringSliceVarP(&flags.outputFormats, "output", "o", formatSplit(cfg.Output), "Output formats: table, json, txt, sarif, html")
	RootCmd.Flags().StringVar(&flags.outputDir, "output-dir", cfg.OutputDir, "Directory for generated report files")
	RootCmd.Flags().StringVar(&flags.failOn, "fail-on", cfg.FailOn, "Fail with exit code 1 if findings at/above severity: Critical, High, Medium, Low")
	RootCmd.Flags().StringVar(&flags.slackWebhook, "slack-webhook", cfg.SlackWebhook, "Slack incoming webhook URL")
	RootCmd.Flags().StringVar(&flags.slackToken, "slack-token", cfg.SlackToken, "Slack bot OAuth token")
	RootCmd.Flags().StringVar(&flags.slackChannel, "slack-channel", cfg.SlackChannel, "Slack channel ID")
	RootCmd.Flags().BoolVar(&flags.slackDisableFile, "slack-disable-file", cfg.SlackDisableFile, "Skip Slack file upload even if a bot token is configured")
	RootCmd.Flags().StringVar(&flags.dbPath, "db-path", cfg.DBPath, "Path to SQLite cache")
	RootCmd.Flags().StringVar(&flags.manifestDir, "manifest-dir", cfg.ManifestDir, "Provider manifest directory")
	RootCmd.Flags().StringVar(&flags.nvdAPIKey, "nvd-api-key", cfg.NVDAPIKey, "NVD API key (optional)")
	RootCmd.Flags().BoolVar(&flags.sync, "sync", false, "Run a cache sync before scanning")

	// Preserve a lightweight local report viewer as a subcommand.
	RootCmd.AddCommand(serveCmd())
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Positional provider overrides --provider if given.
	if len(args) > 0 && args[0] != "" {
		flags.provider = args[0]
	}

	fileCfg, err := loadConfigFile(cmd)
	if err != nil {
		return err
	}

	resolved := input.Resolve(fileCfg, input.Flags{
		Provider:   flags.provider,
		K8sVersion: flags.k8sVersion,
		NodeOS:     flags.nodeOS,
		Components: flags.components,
		Assets:     flags.assets,
		Changed: map[string]bool{
			"provider":    cmd.Flags().Changed("provider") || (len(args) > 0 && args[0] != ""),
			"k8s-version": cmd.Flags().Changed("k8s-version"),
			"node-os":     cmd.Flags().Changed("node-os"),
			"component":   cmd.Flags().Changed("component"),
			"asset":       cmd.Flags().Changed("asset"),
		},
	})

	if err := validateInput(resolved); err != nil {
		return err
	}

	// Initialize cache and scanner.
	cfg := configFromFlags()
	db, err := cache.Open(cfg)
	if err != nil {
		return fmt.Errorf("open cache: %w", err)
	}
	defer db.Close()

	reg := providers.NewRegistry(cfg.ManifestDir)
	sc := scan.New(cfg, db, reg)

	if flags.sync {
		log.Println("syncing cache...")
		runner := &sync.Runner{DB: db, NVDAPIKey: cfg.NVDAPIKey}
		if err := runner.RunAll(ctx); err != nil {
			log.Printf("cache sync warning: %v", err)
		}
		ensureCache(ctx, runner, db)
	}

	results, err := sc.Scan(ctx, resolved)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	report := presenter.BuildReport(resolved, results, flags.failOn)
	pres, err := presenter.NewMany(flags.outputFormats)
	if err != nil {
		return err
	}

	filePaths, err := writeReports(pres, report)
	if err != nil {
		return err
	}

	if err := notifySlack(ctx, report, filePaths); err != nil {
		return err
	}

	exitCode := exit.Code(nil, flags.failOn, results)
	if exitCode != exit.OK {
		os.Exit(exitCode)
	}
	return nil
}

func loadConfigFile(_ *cobra.Command) (input.StackConfig, error) {
	path := flags.configPath
	if path == "" {
		return input.StackConfig{}, nil
	}

	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return input.StackConfig{}, fmt.Errorf("open config: %w", err)
		}
		defer f.Close()
		r = f
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return input.StackConfig{}, fmt.Errorf("read config: %w", err)
	}
	return input.ParseStack(data)
}

func validateInput(input models.ClusterInput) error {
	if input.Provider == "" && len(input.Assets) == 0 {
		return fmt.Errorf("provider or at least one --asset is required")
	}
	return nil
}

func configFromFlags() config.Config {
	cfg := config.Load()
	if flags.dbPath != "" {
		cfg.DBPath = flags.dbPath
	}
	if flags.manifestDir != "" {
		cfg.ManifestDir = flags.manifestDir
	}
	if flags.nvdAPIKey != "" {
		cfg.NVDAPIKey = flags.nvdAPIKey
	}
	return cfg
}

func ensureCache(ctx context.Context, runner *sync.Runner, db *cache.DB) {
	if n, _ := db.CountKEV(ctx); n == 0 {
		log.Println("empty cache: syncing KEV feed...")
		if _, err := runner.RunKEV(ctx); err != nil {
			log.Printf("kev sync: %v", err)
		}
	}
}

// writeReports renders presenters. It returns paths for file-based reports.
func writeReports(pres []presenter.Presenter, report models.ScanReport) ([]string, error) {
	filePres := presenter.FilePresenters(pres)
	hasTable := len(pres) > len(filePres)

	if hasTable {
		tw, ok := presenterByName(pres, "table")
		if !ok {
			return nil, fmt.Errorf("table presenter not found")
		}
		if err := tw.Present(os.Stdout, report); err != nil {
			return nil, fmt.Errorf("write table: %w", err)
		}
	}

	if len(filePres) == 0 {
		return nil, nil
	}

	if err := os.MkdirAll(flags.outputDir, 0o750); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	// If an explicit output file is given and only one file format, route all files there.
	if flags.outputFile != "" && len(filePres) == 1 {
		return []string{flags.outputFile}, writeSingleReport(filePres[0], report, flags.outputFile)
	}
	if flags.outputFile != "" && len(filePres) > 1 {
		log.Println("warning: --output-file ignored when multiple file formats are requested")
	}

	paths := make([]string, 0, len(filePres))
	prefix := "k8sradar-report"
	for _, p := range filePres {
		path := filepath.Join(flags.outputDir, prefix+p.Extension())
		if err := writeSingleReport(p, report, path); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func writeSingleReport(p presenter.Presenter, report models.ScanReport, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if err := p.Present(f, report); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	log.Printf("wrote %s report: %s", p.Name(), path)
	return nil
}

func presenterByName(pres []presenter.Presenter, name string) (presenter.Presenter, bool) {
	for _, p := range pres {
		if p.Name() == name {
			return p, true
		}
	}
	return nil, false
}

func notifySlack(ctx context.Context, report models.ScanReport, files []string) error {
	slackCfg := slackpkg.Config{
		Webhook:     flags.slackWebhook,
		Token:       flags.slackToken,
		Channel:     flags.slackChannel,
		DisableFile: flags.slackDisableFile,
	}

	if slackCfg.Webhook == "" && slackCfg.Token == "" && slackCfg.Channel == "" {
		return nil
	}

	notifier, err := slackpkg.New(slackCfg)
	if err != nil {
		return fmt.Errorf("slack: %w", err)
	}

	summary := slackpkg.SummaryFromReport(report, 5)
	if err := notifier.Notify(ctx, summary, files); err != nil {
		return fmt.Errorf("slack notification: %w", err)
	}
	return nil
}

